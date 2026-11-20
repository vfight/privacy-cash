import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Zkcash } from "../target/types/zkcash";
import {
  ComputeBudgetProgram,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
} from "@solana/web3.js";
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  ExtensionType,
  LENGTH_SIZE,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  TYPE_SIZE,
  createAssociatedTokenAccountIdempotentInstruction,
  createAssociatedTokenAccountInstruction,
  createInitializeMetadataPointerInstruction,
  createInitializeMintInstruction,
  createInitializeNonTransferableMintInstruction,
  createInitializePermanentDelegateInstruction,
  createInitializeTransferFeeConfigInstruction,
  createMintToInstruction,
  getAccount,
  getAssociatedTokenAddressSync,
  getMintLen,
} from "@solana/spl-token";
import {
  createInitializeInstruction as createInitializeTokenMetadataInstruction,
  pack as packTokenMetadata,
} from "@solana/spl-token-metadata";
import { expect } from "chai";
import * as path from "path";
import { BN } from "bn.js";
import { LightWasm, WasmFactory } from "@lightprotocol/hasher.rs";
import { DEFAULT_HEIGHT, FIELD_SIZE } from "./lib/constants";
import { MerkleTree } from "./lib/merkle_tree";
import { Utxo } from "./lib/utxo";
import { Keypair as UtxoKeypair } from "./lib/keypair";
import { parseProofToBytesArray, parseToBytesArray, prove } from "./lib/prover";
import { getExtDataHash, getMintAddressField } from "./lib/utils";
import {
  createGlobalTestALT,
  createVersionedTransactionWithALT,
  resetGlobalTestALT,
  sendAndConfirmVersionedTransaction,
} from "./lib/test_alt";

const SOL_ADDRESS = new PublicKey("11111111111111111111111111111112");
const KEY_BASE_PATH = path.resolve(__dirname, "../../artifacts/circuits/transaction2");

function findNullifierPDAs(programId: PublicKey, proof: { inputNullifiers: number[][] }) {
  const [nullifier0PDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier0"), Buffer.from(proof.inputNullifiers[0])],
    programId
  );
  const [nullifier1PDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier1"), Buffer.from(proof.inputNullifiers[1])],
    programId
  );
  const [nullifier2PDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier0"), Buffer.from(proof.inputNullifiers[1])],
    programId
  );
  const [nullifier3PDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier1"), Buffer.from(proof.inputNullifiers[0])],
    programId
  );
  return { nullifier0PDA, nullifier1PDA, nullifier2PDA, nullifier3PDA };
}

async function expectError(promise: Promise<unknown>, expectedSubstring: string) {
  let failed = false;
  try {
    await promise;
  } catch (err: any) {
    failed = true;
    const text = `${err?.message ?? ""} ${JSON.stringify(err?.logs ?? "")}`;
    expect(text, `Expected error containing "${expectedSubstring}", got: ${text}`).to.include(expectedSubstring);
  }
  expect(failed, `Expected failure with "${expectedSubstring}" but transaction succeeded`).to.be.true;
}

describe("zkcash any-token (SPL + Token-2022 + permissionless init + fee floor + fee_recipient)", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.Zkcash as Program<Zkcash>;

  let lightWasm: LightWasm;
  let admin: Keypair;
  let randomUser: Keypair;
  let relayer: Keypair;
  let treasury: Keypair;
  let globalConfigPDA: PublicKey;
  let solTreePDA: PublicKey;
  let solTreeTokenPDA: PublicKey;
  let altAddress: PublicKey;

  let solMerkleTree: MerkleTree;
  let splMint: Keypair;
  let splTreePDA: PublicKey;
  let splTreeAta: PublicKey;
  let splMerkleTree: MerkleTree;

  let t22Mint: Keypair;
  let t22TreePDA: PublicKey;
  let t22TreeAta: PublicKey;
  let t22MerkleTree: MerkleTree;

  async function fund(pubkey: PublicKey, sol = 5) {
    const sig = await provider.connection.requestAirdrop(pubkey, sol * LAMPORTS_PER_SOL);
    const bh = await provider.connection.getLatestBlockhash();
    await provider.connection.confirmTransaction({ signature: sig, ...bh });
  }

  async function buildProof(params: {
    tree: MerkleTree;
    mint: PublicKey;
    inputs: Utxo[];
    outputs: Utxo[];
    extAmount: BN;
    fee: BN;
    recipient: PublicKey;
    feeRecipient: PublicKey;
    encryptedOutput1: Buffer;
    encryptedOutput2: Buffer;
  }) {
    const { tree, mint, inputs, outputs, extAmount, fee, recipient, feeRecipient, encryptedOutput1, encryptedOutput2 } = params;
    const root = tree.root();
    const inputPathIndices = inputs.map((u) => (u.amount.gt(new BN(0)) ? u.index : 0));
    const inputPathElements = await Promise.all(
      inputs.map(async (u) => {
        if (u.amount.gt(new BN(0))) {
          const commitment = await u.getCommitment();
          const idx = tree.indexOf(commitment);
          if (idx < 0) throw new Error(`Commitment not found in local tree: ${commitment}`);
          return tree.path(idx).pathElements;
        }
        return new Array(DEFAULT_HEIGHT).fill("0");
      })
    );
    const inputNullifiers = await Promise.all(inputs.map((u) => u.getNullifier()));
    const outputCommitments = await Promise.all(outputs.map((u) => u.getCommitment()));
    const publicAmount = extAmount.sub(fee).add(FIELD_SIZE).mod(FIELD_SIZE);
    const extDataHash = getExtDataHash({
      recipient,
      extAmount,
      encryptedOutput1,
      encryptedOutput2,
      fee,
      feeRecipient,
      mintAddress: mint,
    });
    const circuitInput = {
      root,
      mintAddress: getMintAddressField(mint),
      publicAmount: publicAmount.toString(),
      extDataHash,
      inAmount: inputs.map((u) => u.amount.toString(10)),
      inPrivateKey: inputs.map((u) => u.keypair.privkey),
      inBlinding: inputs.map((u) => u.blinding.toString(10)),
      inPathIndices: inputPathIndices,
      inPathElements: inputPathElements,
      inputNullifier: inputNullifiers,
      outAmount: outputs.map((u) => u.amount.toString(10)),
      outBlinding: outputs.map((u) => u.blinding.toString(10)),
      outPubkey: outputs.map((u) => u.keypair.pubkey),
      outputCommitment: outputCommitments,
    };
    const { proof, publicSignals } = await prove(circuitInput, KEY_BASE_PATH);
    const proofInBytes = parseProofToBytesArray(proof);
    const inputsInBytes = parseToBytesArray(publicSignals);
    return {
      proofArg: {
        proofA: proofInBytes.proofA,
        proofB: proofInBytes.proofB.flat(),
        proofC: proofInBytes.proofC,
        root: inputsInBytes[0],
        publicAmount: inputsInBytes[1],
        extDataHash: inputsInBytes[2],
        inputNullifiers: [inputsInBytes[3], inputsInBytes[4]],
        outputCommitments: [inputsInBytes[5], inputsInBytes[6]],
      },
      outputCommitments,
    };
  }

  before(async () => {
    lightWasm = await WasmFactory.getInstance();
    admin = Keypair.generate();
    randomUser = Keypair.generate();
    relayer = Keypair.generate();
    treasury = Keypair.generate();

    await Promise.all([
      fund(admin.publicKey, 10),
      fund(randomUser.publicKey, 10),
      fund(relayer.publicKey, 10),
      fund(treasury.publicKey, 2),
    ]);

    [globalConfigPDA] = PublicKey.findProgramAddressSync([Buffer.from("global_config")], program.programId);
    [solTreePDA] = PublicKey.findProgramAddressSync([Buffer.from("merkle_tree")], program.programId);
    [solTreeTokenPDA] = PublicKey.findProgramAddressSync([Buffer.from("tree_token")], program.programId);

    solMerkleTree = new MerkleTree(DEFAULT_HEIGHT, lightWasm);
    splMerkleTree = new MerkleTree(DEFAULT_HEIGHT, lightWasm);
    t22MerkleTree = new MerkleTree(DEFAULT_HEIGHT, lightWasm);

    await program.methods
      .initialize()
      .accountsPartial({
        treeAccount: solTreePDA,
        treeTokenAccount: solTreeTokenPDA,
        globalConfig: globalConfigPDA,
        authority: admin.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([admin])
      .rpc();

    resetGlobalTestALT();
    altAddress = await createGlobalTestALT(provider.connection, admin, [
      program.programId,
      solTreePDA,
      solTreeTokenPDA,
      globalConfigPDA,
      admin.publicKey,
      treasury.publicKey,
      SystemProgram.programId,
      ComputeBudgetProgram.programId,
      ASSOCIATED_TOKEN_PROGRAM_ID,
      TOKEN_PROGRAM_ID,
      TOKEN_2022_PROGRAM_ID,
    ]);
  });

  it("initializes global_config with fee_recipient and allows only admin to update it", async () => {
    const cfg = await program.account.globalConfig.fetch(globalConfigPDA);
    expect(cfg.authority.equals(admin.publicKey)).to.be.true;
    expect(cfg.feeRecipient.equals(admin.publicKey)).to.be.true;

    // Non-admin rejected
    await expectError(
      program.methods
        .updateGlobalConfig(null, null, null, treasury.publicKey)
        .accountsPartial({
          globalConfig: globalConfigPDA,
          authority: randomUser.publicKey,
        })
        .signers([randomUser])
        .rpc(),
      "Unauthorized"
    );

    // Zero pubkey rejected
    await expectError(
      program.methods
        .updateGlobalConfig(null, null, null, PublicKey.default)
        .accountsPartial({
          globalConfig: globalConfigPDA,
          authority: admin.publicKey,
        })
        .signers([admin])
        .rpc(),
      "InvalidFeeRecipient"
    );

    // Admin updates fee_recipient to treasury
    await program.methods
      .updateGlobalConfig(null, null, null, treasury.publicKey)
      .accountsPartial({
        globalConfig: globalConfigPDA,
        authority: admin.publicKey,
      })
      .signers([admin])
      .rpc();

    const updated = await program.account.globalConfig.fetch(globalConfigPDA);
    expect(updated.feeRecipient.equals(treasury.publicKey)).to.be.true;
  });

  it("allows any non-admin user to initialize Merkle trees for arbitrary legacy SPL and Token-2022 (Metadata) mints", async () => {
    // 1. Create a brand-new legacy SPL mint
    splMint = Keypair.generate();
    const splMintRent = await provider.connection.getMinimumBalanceForRentExemption(82);
    await provider.sendAndConfirm(
      new Transaction().add(
        SystemProgram.createAccount({
          fromPubkey: randomUser.publicKey,
          newAccountPubkey: splMint.publicKey,
          space: 82,
          lamports: splMintRent,
          programId: TOKEN_PROGRAM_ID,
        }),
        createInitializeMintInstruction(splMint.publicKey, 6, randomUser.publicKey, randomUser.publicKey, TOKEN_PROGRAM_ID)
      ),
      [randomUser, splMint]
    );

    [splTreePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("merkle_tree"), splMint.publicKey.toBuffer()],
      program.programId
    );
    splTreeAta = getAssociatedTokenAddressSync(splMint.publicKey, globalConfigPDA, true, TOKEN_PROGRAM_ID);

    // Non-admin initializes legacy SPL tree
    await program.methods
      .initializeTreeAccountForSplToken()
      .accountsPartial({
        treeAccount: splTreePDA,
        mint: splMint.publicKey,
        treeAta: splTreeAta,
        globalConfig: globalConfigPDA,
        payer: randomUser.publicKey,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .signers([randomUser])
      .rpc();

    const splTree = await program.account.merkleTreeAccount.fetch(splTreePDA);
    expect(splTree.authority.equals(admin.publicKey)).to.be.true;
    expect(splTree.minDepositFee.toString()).to.equal("0");
    expect(splTree.minWithdrawalFee.toString()).to.equal("0");
    expect(splTree.maxDepositAmount.toString()).to.equal("9223372036854775807");

    // 2. Create a Token-2022 mint with MetadataPointer + TokenMetadata (exact VBC profile)
    t22Mint = Keypair.generate();
    const metadata = {
      mint: t22Mint.publicKey,
      name: "Radar Coin",
      symbol: "VBC",
      uri: "https://radarlab.top/metadata.json",
      additionalMetadata: [] as [string, string][],
    };
    const mintLen = getMintLen([ExtensionType.MetadataPointer]);
    const metadataLen = TYPE_SIZE + LENGTH_SIZE + packTokenMetadata(metadata).length;
    const t22Lamports = await provider.connection.getMinimumBalanceForRentExemption(mintLen + metadataLen);
    await provider.sendAndConfirm(
      new Transaction().add(
        SystemProgram.createAccount({
          fromPubkey: randomUser.publicKey,
          newAccountPubkey: t22Mint.publicKey,
          space: mintLen,
          lamports: t22Lamports,
          programId: TOKEN_2022_PROGRAM_ID,
        }),
        createInitializeMetadataPointerInstruction(
          t22Mint.publicKey,
          randomUser.publicKey,
          t22Mint.publicKey,
          TOKEN_2022_PROGRAM_ID
        ),
        createInitializeMintInstruction(t22Mint.publicKey, 9, randomUser.publicKey, null, TOKEN_2022_PROGRAM_ID),
        createInitializeTokenMetadataInstruction({
          programId: TOKEN_2022_PROGRAM_ID,
          mint: t22Mint.publicKey,
          metadata: t22Mint.publicKey,
          mintAuthority: randomUser.publicKey,
          name: metadata.name,
          symbol: metadata.symbol,
          uri: metadata.uri,
          updateAuthority: randomUser.publicKey,
        })
      ),
      [randomUser, t22Mint]
    );

    [t22TreePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("merkle_tree"), t22Mint.publicKey.toBuffer()],
      program.programId
    );
    t22TreeAta = getAssociatedTokenAddressSync(t22Mint.publicKey, globalConfigPDA, true, TOKEN_2022_PROGRAM_ID);

    // Non-admin initializes Token-2022 tree
    await program.methods
      .initializeTreeAccountForSplToken()
      .accountsPartial({
        treeAccount: t22TreePDA,
        mint: t22Mint.publicKey,
        treeAta: t22TreeAta,
        globalConfig: globalConfigPDA,
        payer: randomUser.publicKey,
        tokenProgram: TOKEN_2022_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .signers([randomUser])
      .rpc();

    const t22Tree = await program.account.merkleTreeAccount.fetch(t22TreePDA);
    expect(t22Tree.authority.equals(admin.publicKey)).to.be.true;
    expect(t22Tree.minWithdrawalFee.toString()).to.equal("0");

    // Non-admin who paid for tree init CANNOT update tree config
    await expectError(
      program.methods
        .updateTreeConfigForSplToken(new BN(1), null, null)
        .accountsPartial({
          treeAccount: t22TreePDA,
          mint: t22Mint.publicKey,
          authority: randomUser.publicKey,
        })
        .signers([randomUser])
        .rpc(),
      "Unauthorized"
    );
  });

  it("rejects Token-2022 mints with dangerous extensions (TransferFee, PermanentDelegate, NonTransferable)", async () => {
    // 1. TransferFeeConfig (even 0 bps!)
    const feeMint = Keypair.generate();
    const feeMintLen = getMintLen([ExtensionType.TransferFeeConfig]);
    const feeRent = await provider.connection.getMinimumBalanceForRentExemption(feeMintLen);
    await provider.sendAndConfirm(
      new Transaction().add(
        SystemProgram.createAccount({
          fromPubkey: randomUser.publicKey,
          newAccountPubkey: feeMint.publicKey,
          space: feeMintLen,
          lamports: feeRent,
          programId: TOKEN_2022_PROGRAM_ID,
        }),
        createInitializeTransferFeeConfigInstruction(
          feeMint.publicKey,
          randomUser.publicKey,
          randomUser.publicKey,
          0,
          0n,
          TOKEN_2022_PROGRAM_ID
        ),
        createInitializeMintInstruction(feeMint.publicKey, 9, randomUser.publicKey, null, TOKEN_2022_PROGRAM_ID)
      ),
      [randomUser, feeMint]
    );
    const [feeTreePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("merkle_tree"), feeMint.publicKey.toBuffer()],
      program.programId
    );
    const feeTreeAta = getAssociatedTokenAddressSync(feeMint.publicKey, globalConfigPDA, true, TOKEN_2022_PROGRAM_ID);
    await expectError(
      program.methods
        .initializeTreeAccountForSplToken()
        .accountsPartial({
          treeAccount: feeTreePDA,
          mint: feeMint.publicKey,
          treeAta: feeTreeAta,
          globalConfig: globalConfigPDA,
          payer: randomUser.publicKey,
          tokenProgram: TOKEN_2022_PROGRAM_ID,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .signers([randomUser])
        .rpc(),
      "UnsupportedMintExtension"
    );

    // 2. PermanentDelegate
    const pdMint = Keypair.generate();
    const pdMintLen = getMintLen([ExtensionType.PermanentDelegate]);
    const pdRent = await provider.connection.getMinimumBalanceForRentExemption(pdMintLen);
    await provider.sendAndConfirm(
      new Transaction().add(
        SystemProgram.createAccount({
          fromPubkey: randomUser.publicKey,
          newAccountPubkey: pdMint.publicKey,
          space: pdMintLen,
          lamports: pdRent,
          programId: TOKEN_2022_PROGRAM_ID,
        }),
        createInitializePermanentDelegateInstruction(pdMint.publicKey, randomUser.publicKey, TOKEN_2022_PROGRAM_ID),
        createInitializeMintInstruction(pdMint.publicKey, 9, randomUser.publicKey, null, TOKEN_2022_PROGRAM_ID)
      ),
      [randomUser, pdMint]
    );
    const [pdTreePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("merkle_tree"), pdMint.publicKey.toBuffer()],
      program.programId
    );
    const pdTreeAta = getAssociatedTokenAddressSync(pdMint.publicKey, globalConfigPDA, true, TOKEN_2022_PROGRAM_ID);
    await expectError(
      program.methods
        .initializeTreeAccountForSplToken()
        .accountsPartial({
          treeAccount: pdTreePDA,
          mint: pdMint.publicKey,
          treeAta: pdTreeAta,
          globalConfig: globalConfigPDA,
          payer: randomUser.publicKey,
          tokenProgram: TOKEN_2022_PROGRAM_ID,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .signers([randomUser])
        .rpc(),
      "UnsupportedMintExtension"
    );

    // 3. NonTransferable
    const ntMint = Keypair.generate();
    const ntMintLen = getMintLen([ExtensionType.NonTransferable]);
    const ntRent = await provider.connection.getMinimumBalanceForRentExemption(ntMintLen);
    await provider.sendAndConfirm(
      new Transaction().add(
        SystemProgram.createAccount({
          fromPubkey: randomUser.publicKey,
          newAccountPubkey: ntMint.publicKey,
          space: ntMintLen,
          lamports: ntRent,
          programId: TOKEN_2022_PROGRAM_ID,
        }),
        createInitializeNonTransferableMintInstruction(ntMint.publicKey, TOKEN_2022_PROGRAM_ID),
        createInitializeMintInstruction(ntMint.publicKey, 9, randomUser.publicKey, null, TOKEN_2022_PROGRAM_ID)
      ),
      [randomUser, ntMint]
    );
    const [ntTreePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("merkle_tree"), ntMint.publicKey.toBuffer()],
      program.programId
    );
    const ntTreeAta = getAssociatedTokenAddressSync(ntMint.publicKey, globalConfigPDA, true, TOKEN_2022_PROGRAM_ID);
    await expectError(
      program.methods
        .initializeTreeAccountForSplToken()
        .accountsPartial({
          treeAccount: ntTreePDA,
          mint: ntMint.publicKey,
          treeAta: ntTreeAta,
          globalConfig: globalConfigPDA,
          payer: randomUser.publicKey,
          tokenProgram: TOKEN_2022_PROGRAM_ID,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .signers([randomUser])
        .rpc(),
      "UnsupportedMintExtension"
    );
  });

  it("runs full Token-2022 (VBC-like) deposit, per-mint min_withdrawal_fee floor, fee_recipient check, and relayed withdraw", async () => {
    // Mint 10,000 VBC (9 decimals) to randomUser
    const userAta = getAssociatedTokenAddressSync(t22Mint.publicKey, randomUser.publicKey, false, TOKEN_2022_PROGRAM_ID);
    await provider.sendAndConfirm(
      new Transaction().add(
        createAssociatedTokenAccountInstruction(
          randomUser.publicKey,
          userAta,
          randomUser.publicKey,
          t22Mint.publicKey,
          TOKEN_2022_PROGRAM_ID
        ),
        createMintToInstruction(
          t22Mint.publicKey,
          userAta,
          randomUser.publicKey,
          10_000n * 1_000_000_000n,
          [],
          TOKEN_2022_PROGRAM_ID
        )
      ),
      [randomUser]
    );

    const treasuryT22Ata = getAssociatedTokenAddressSync(t22Mint.publicKey, treasury.publicKey, true, TOKEN_2022_PROGRAM_ID);
    // Note: treasuryT22Ata does NOT exist yet! Deposit with fee == 0 must still succeed!
    const utxoKeypair = UtxoKeypair.generateNew(lightWasm);

    // 1. Deposit 5,000 VBC
    const depositAmount = new BN("5000000000000"); // 5000 * 1e9
    const dummyIn1 = new Utxo({ lightWasm, amount: 0, keypair: utxoKeypair, mintAddress: t22Mint.publicKey.toBase58() });
    const dummyIn2 = new Utxo({ lightWasm, amount: 0, keypair: utxoKeypair, mintAddress: t22Mint.publicKey.toBase58() });
    const out1 = new Utxo({ lightWasm, amount: depositAmount, keypair: utxoKeypair, index: 0, mintAddress: t22Mint.publicKey.toBase58() });
    const out2 = new Utxo({ lightWasm, amount: 0, keypair: utxoKeypair, index: 1, mintAddress: t22Mint.publicKey.toBase58() });
    const enc1 = Buffer.from("t22_dep_out1");
    const enc2 = Buffer.from("t22_dep_out2");

    const { proofArg: depProof, outputCommitments: depCommits } = await buildProof({
      tree: t22MerkleTree,
      mint: t22Mint.publicKey,
      inputs: [dummyIn1, dummyIn2],
      outputs: [out1, out2],
      extAmount: depositAmount,
      fee: new BN(0),
      recipient: treasuryT22Ata,
      feeRecipient: treasuryT22Ata,
      encryptedOutput1: enc1,
      encryptedOutput2: enc2,
    });
    const depNullifiers = findNullifierPDAs(program.programId, depProof);
    const depIx = await program.methods
      .transactSpl(depProof as any, { extAmount: depositAmount, fee: new BN(0) }, enc1, enc2)
      .accountsPartial({
        treeAccount: t22TreePDA,
        nullifier0: depNullifiers.nullifier0PDA,
        nullifier1: depNullifiers.nullifier1PDA,
        nullifier2: depNullifiers.nullifier2PDA,
        nullifier3: depNullifiers.nullifier3PDA,
        globalConfig: globalConfigPDA,
        signer: randomUser.publicKey,
        mint: t22Mint.publicKey,
        signerTokenAccount: userAta,
        recipient: treasury.publicKey,
        recipientTokenAccount: treasuryT22Ata,
        treeAta: t22TreeAta,
        feeRecipientAta: treasuryT22Ata,
        tokenProgram: TOKEN_2022_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .instruction();

    const depTx = await createVersionedTransactionWithALT(
      provider.connection,
      randomUser.publicKey,
      [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }), depIx],
      altAddress
    );
    await sendAndConfirmVersionedTransaction(provider.connection, depTx, [randomUser]);
    t22MerkleTree.insert(depCommits[0]);
    t22MerkleTree.insert(depCommits[1]);

    const vaultAfterDep = await getAccount(provider.connection, t22TreeAta, undefined, TOKEN_2022_PROGRAM_ID);
    expect(vaultAfterDep.amount.toString()).to.equal(depositAmount.toString());

    // 2. Admin configures per-mint min_withdrawal_fee = 5 VBC (5 * 1e9)
    const minWithdrawFee = new BN("5000000000");
    await program.methods
      .updateTreeConfigForSplToken(null, null, minWithdrawFee)
      .accountsPartial({
        treeAccount: t22TreePDA,
        mint: t22Mint.publicKey,
        authority: admin.publicKey,
      })
      .signers([admin])
      .rpc();

    const freshRecipient = Keypair.generate();
    const recipientAta = getAssociatedTokenAddressSync(t22Mint.publicKey, freshRecipient.publicKey, false, TOKEN_2022_PROGRAM_ID);

    // 3a. Withdraw 100 VBC with wrong fee_recipient_ata -> rejected with InvalidFeeRecipient
    const wrongFeeAta = getAssociatedTokenAddressSync(t22Mint.publicKey, randomUser.publicKey, false, TOKEN_2022_PROGRAM_ID);
    const smallWithdraw = new BN("100000000000"); // 100 VBC (0.25% = 0.25 VBC < 5 VBC floor)
    {
      const change = depositAmount.sub(smallWithdraw).sub(minWithdrawFee);
      const wOut1 = new Utxo({ lightWasm, amount: change, keypair: utxoKeypair, index: 2, mintAddress: t22Mint.publicKey.toBase58() });
      const wOut2 = new Utxo({ lightWasm, amount: 0, keypair: utxoKeypair, index: 3, mintAddress: t22Mint.publicKey.toBase58() });
      const { proofArg } = await buildProof({
        tree: t22MerkleTree,
        mint: t22Mint.publicKey,
        inputs: [out1, dummyIn2],
        outputs: [wOut1, wOut2],
        extAmount: smallWithdraw.neg(),
        fee: minWithdrawFee,
        recipient: recipientAta,
        feeRecipient: wrongFeeAta,
        encryptedOutput1: enc1,
        encryptedOutput2: enc2,
      });
      const n = findNullifierPDAs(program.programId, proofArg);
      const ix = await program.methods
        .transactSpl(proofArg as any, { extAmount: smallWithdraw.neg(), fee: minWithdrawFee }, enc1, enc2)
        .accountsPartial({
          treeAccount: t22TreePDA,
          nullifier0: n.nullifier0PDA,
          nullifier1: n.nullifier1PDA,
          nullifier2: n.nullifier2PDA,
          nullifier3: n.nullifier3PDA,
          globalConfig: globalConfigPDA,
          signer: relayer.publicKey,
          mint: t22Mint.publicKey,
          signerTokenAccount: relayer.publicKey, // Relayer has NO ATA for this token!
          recipient: freshRecipient.publicKey,
          recipientTokenAccount: recipientAta,
          treeAta: t22TreeAta,
          feeRecipientAta: wrongFeeAta,
          tokenProgram: TOKEN_2022_PROGRAM_ID,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .instruction();
      const tx = await createVersionedTransactionWithALT(
        provider.connection,
        relayer.publicKey,
        [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }), ix],
        altAddress
      );
      await expectError(sendAndConfirmVersionedTransaction(provider.connection, tx, [relayer]), "InvalidFeeRecipient");
    }

    // 3b. Withdraw 100 VBC with fee = 1 VBC (above 0.25% rate, but below 5 VBC floor) -> InvalidFeeAmount
    {
      const tooLowFee = new BN("1000000000"); // 1 VBC
      const change = depositAmount.sub(smallWithdraw).sub(tooLowFee);
      const wOut1 = new Utxo({ lightWasm, amount: change, keypair: utxoKeypair, index: 2, mintAddress: t22Mint.publicKey.toBase58() });
      const wOut2 = new Utxo({ lightWasm, amount: 0, keypair: utxoKeypair, index: 3, mintAddress: t22Mint.publicKey.toBase58() });
      const { proofArg } = await buildProof({
        tree: t22MerkleTree,
        mint: t22Mint.publicKey,
        inputs: [out1, dummyIn2],
        outputs: [wOut1, wOut2],
        extAmount: smallWithdraw.neg(),
        fee: tooLowFee,
        recipient: recipientAta,
        feeRecipient: treasuryT22Ata,
        encryptedOutput1: enc1,
        encryptedOutput2: enc2,
      });
      const n = findNullifierPDAs(program.programId, proofArg);
      const ix = await program.methods
        .transactSpl(proofArg as any, { extAmount: smallWithdraw.neg(), fee: tooLowFee }, enc1, enc2)
        .accountsPartial({
          treeAccount: t22TreePDA,
          nullifier0: n.nullifier0PDA,
          nullifier1: n.nullifier1PDA,
          nullifier2: n.nullifier2PDA,
          nullifier3: n.nullifier3PDA,
          globalConfig: globalConfigPDA,
          signer: relayer.publicKey,
          mint: t22Mint.publicKey,
          signerTokenAccount: relayer.publicKey,
          recipient: freshRecipient.publicKey,
          recipientTokenAccount: recipientAta,
          treeAta: t22TreeAta,
          feeRecipientAta: treasuryT22Ata,
          tokenProgram: TOKEN_2022_PROGRAM_ID,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .instruction();
      const tx = await createVersionedTransactionWithALT(
        provider.connection,
        relayer.publicKey,
        [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }), ix],
        altAddress
      );
      await expectError(sendAndConfirmVersionedTransaction(provider.connection, tx, [relayer]), "InvalidFeeAmount");
    }

    // 3c. Withdraw 100 VBC with exact floor fee = 5 VBC, relayed by relayer (no relayer ATA needed!)
    const changeAfterFirst = depositAmount.sub(smallWithdraw).sub(minWithdrawFee); // 4895 VBC
    const wOut1 = new Utxo({ lightWasm, amount: changeAfterFirst, keypair: utxoKeypair, index: 2, mintAddress: t22Mint.publicKey.toBase58() });
    const wOut2 = new Utxo({ lightWasm, amount: 0, keypair: utxoKeypair, index: 3, mintAddress: t22Mint.publicKey.toBase58() });
    {
      const { proofArg, outputCommitments } = await buildProof({
        tree: t22MerkleTree,
        mint: t22Mint.publicKey,
        inputs: [out1, dummyIn2],
        outputs: [wOut1, wOut2],
        extAmount: smallWithdraw.neg(),
        fee: minWithdrawFee,
        recipient: recipientAta,
        feeRecipient: treasuryT22Ata,
        encryptedOutput1: enc1,
        encryptedOutput2: enc2,
      });
      const n = findNullifierPDAs(program.programId, proofArg);
      const createRecipientAtaIx = createAssociatedTokenAccountIdempotentInstruction(
        relayer.publicKey,
        recipientAta,
        freshRecipient.publicKey,
        t22Mint.publicKey,
        TOKEN_2022_PROGRAM_ID
      );
      const createTreasuryAtaIx = createAssociatedTokenAccountIdempotentInstruction(
        relayer.publicKey,
        treasuryT22Ata,
        treasury.publicKey,
        t22Mint.publicKey,
        TOKEN_2022_PROGRAM_ID
      );
      const ix = await program.methods
        .transactSpl(proofArg as any, { extAmount: smallWithdraw.neg(), fee: minWithdrawFee }, enc1, enc2)
        .accountsPartial({
          treeAccount: t22TreePDA,
          nullifier0: n.nullifier0PDA,
          nullifier1: n.nullifier1PDA,
          nullifier2: n.nullifier2PDA,
          nullifier3: n.nullifier3PDA,
          globalConfig: globalConfigPDA,
          signer: relayer.publicKey,
          mint: t22Mint.publicKey,
          signerTokenAccount: relayer.publicKey,
          recipient: freshRecipient.publicKey,
          recipientTokenAccount: recipientAta,
          treeAta: t22TreeAta,
          feeRecipientAta: treasuryT22Ata,
          tokenProgram: TOKEN_2022_PROGRAM_ID,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .instruction();
      const tx = await createVersionedTransactionWithALT(
        provider.connection,
        relayer.publicKey,
        [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }), createRecipientAtaIx, createTreasuryAtaIx, ix],
        altAddress
      );
      await sendAndConfirmVersionedTransaction(provider.connection, tx, [relayer]);
      t22MerkleTree.insert(outputCommitments[0]);
      t22MerkleTree.insert(outputCommitments[1]);
    }

    const recAcc = await getAccount(provider.connection, recipientAta, undefined, TOKEN_2022_PROGRAM_ID);
    const feeAcc = await getAccount(provider.connection, treasuryT22Ata, undefined, TOKEN_2022_PROGRAM_ID);
    expect(recAcc.amount.toString()).to.equal(smallWithdraw.toString());
    expect(feeAcc.amount.toString()).to.equal(minWithdrawFee.toString());

    // 4. Large withdraw (4,000 VBC -> 0.25% rate = 10 VBC > 5 VBC floor) -> rate governs!
    const largeWithdraw = new BN("4000000000000"); // 4000 VBC
    const largeRateFee = new BN("10000000000"); // 10 VBC
    // Using only floor 5 VBC must fail because rate_min = 9.5 VBC > 5 VBC
    {
      const change = changeAfterFirst.sub(largeWithdraw).sub(minWithdrawFee);
      const lOut1 = new Utxo({ lightWasm, amount: change, keypair: utxoKeypair, index: 4, mintAddress: t22Mint.publicKey.toBase58() });
      const lOut2 = new Utxo({ lightWasm, amount: 0, keypair: utxoKeypair, index: 5, mintAddress: t22Mint.publicKey.toBase58() });
      const { proofArg } = await buildProof({
        tree: t22MerkleTree,
        mint: t22Mint.publicKey,
        inputs: [wOut1, dummyIn2],
        outputs: [lOut1, lOut2],
        extAmount: largeWithdraw.neg(),
        fee: minWithdrawFee,
        recipient: recipientAta,
        feeRecipient: treasuryT22Ata,
        encryptedOutput1: enc1,
        encryptedOutput2: enc2,
      });
      const n = findNullifierPDAs(program.programId, proofArg);
      const ix = await program.methods
        .transactSpl(proofArg as any, { extAmount: largeWithdraw.neg(), fee: minWithdrawFee }, enc1, enc2)
        .accountsPartial({
          treeAccount: t22TreePDA,
          nullifier0: n.nullifier0PDA,
          nullifier1: n.nullifier1PDA,
          nullifier2: n.nullifier2PDA,
          nullifier3: n.nullifier3PDA,
          globalConfig: globalConfigPDA,
          signer: relayer.publicKey,
          mint: t22Mint.publicKey,
          signerTokenAccount: relayer.publicKey,
          recipient: freshRecipient.publicKey,
          recipientTokenAccount: recipientAta,
          treeAta: t22TreeAta,
          feeRecipientAta: treasuryT22Ata,
          tokenProgram: TOKEN_2022_PROGRAM_ID,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .instruction();
      const tx = await createVersionedTransactionWithALT(
        provider.connection,
        relayer.publicKey,
        [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }), ix],
        altAddress
      );
      await expectError(sendAndConfirmVersionedTransaction(provider.connection, tx, [relayer]), "InvalidFeeAmount");
    }

    // With 10 VBC rate fee -> succeeds!
    {
      const change = changeAfterFirst.sub(largeWithdraw).sub(largeRateFee);
      const lOut1 = new Utxo({ lightWasm, amount: change, keypair: utxoKeypair, index: 4, mintAddress: t22Mint.publicKey.toBase58() });
      const lOut2 = new Utxo({ lightWasm, amount: 0, keypair: utxoKeypair, index: 5, mintAddress: t22Mint.publicKey.toBase58() });
      const { proofArg, outputCommitments } = await buildProof({
        tree: t22MerkleTree,
        mint: t22Mint.publicKey,
        inputs: [wOut1, dummyIn2],
        outputs: [lOut1, lOut2],
        extAmount: largeWithdraw.neg(),
        fee: largeRateFee,
        recipient: recipientAta,
        feeRecipient: treasuryT22Ata,
        encryptedOutput1: enc1,
        encryptedOutput2: enc2,
      });
      const n = findNullifierPDAs(program.programId, proofArg);
      const ix = await program.methods
        .transactSpl(proofArg as any, { extAmount: largeWithdraw.neg(), fee: largeRateFee }, enc1, enc2)
        .accountsPartial({
          treeAccount: t22TreePDA,
          nullifier0: n.nullifier0PDA,
          nullifier1: n.nullifier1PDA,
          nullifier2: n.nullifier2PDA,
          nullifier3: n.nullifier3PDA,
          globalConfig: globalConfigPDA,
          signer: relayer.publicKey,
          mint: t22Mint.publicKey,
          signerTokenAccount: relayer.publicKey,
          recipient: freshRecipient.publicKey,
          recipientTokenAccount: recipientAta,
          treeAta: t22TreeAta,
          feeRecipientAta: treasuryT22Ata,
          tokenProgram: TOKEN_2022_PROGRAM_ID,
          associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .instruction();
      const tx = await createVersionedTransactionWithALT(
        provider.connection,
        relayer.publicKey,
        [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }), ix],
        altAddress
      );
      await sendAndConfirmVersionedTransaction(provider.connection, tx, [relayer]);
      t22MerkleTree.insert(outputCommitments[0]);
      t22MerkleTree.insert(outputCommitments[1]);
    }

    const recAcc2 = await getAccount(provider.connection, recipientAta, undefined, TOKEN_2022_PROGRAM_ID);
    const feeAcc2 = await getAccount(provider.connection, treasuryT22Ata, undefined, TOKEN_2022_PROGRAM_ID);
    expect(recAcc2.amount.toString()).to.equal(smallWithdraw.add(largeWithdraw).toString());
    expect(feeAcc2.amount.toString()).to.equal(minWithdrawFee.add(largeRateFee).toString());
  });

  it("runs legacy SPL deposit and relayed withdraw with treasury fee_recipient", async () => {
    const userSplAta = getAssociatedTokenAddressSync(splMint.publicKey, randomUser.publicKey, false, TOKEN_PROGRAM_ID);
    await provider.sendAndConfirm(
      new Transaction().add(
        createAssociatedTokenAccountInstruction(randomUser.publicKey, userSplAta, randomUser.publicKey, splMint.publicKey, TOKEN_PROGRAM_ID),
        createMintToInstruction(splMint.publicKey, userSplAta, randomUser.publicKey, 1_000_000_000n, [], TOKEN_PROGRAM_ID)
      ),
      [randomUser]
    );

    const treasurySplAta = getAssociatedTokenAddressSync(splMint.publicKey, treasury.publicKey, true, TOKEN_PROGRAM_ID);
    const utxoKeypair = UtxoKeypair.generateNew(lightWasm);
    const depositAmount = new BN(500_000_000); // 500 tokens (6 dec)
    const dummyIn1 = new Utxo({ lightWasm, amount: 0, keypair: utxoKeypair, mintAddress: splMint.publicKey.toBase58() });
    const dummyIn2 = new Utxo({ lightWasm, amount: 0, keypair: utxoKeypair, mintAddress: splMint.publicKey.toBase58() });
    const out1 = new Utxo({ lightWasm, amount: depositAmount, keypair: utxoKeypair, index: 0, mintAddress: splMint.publicKey.toBase58() });
    const out2 = new Utxo({ lightWasm, amount: 0, keypair: utxoKeypair, index: 1, mintAddress: splMint.publicKey.toBase58() });
    const enc1 = Buffer.from("spl_dep1");
    const enc2 = Buffer.from("spl_dep2");

    const { proofArg: depProof, outputCommitments: depCommits } = await buildProof({
      tree: splMerkleTree,
      mint: splMint.publicKey,
      inputs: [dummyIn1, dummyIn2],
      outputs: [out1, out2],
      extAmount: depositAmount,
      fee: new BN(0),
      recipient: treasurySplAta,
      feeRecipient: treasurySplAta,
      encryptedOutput1: enc1,
      encryptedOutput2: enc2,
    });
    const dn = findNullifierPDAs(program.programId, depProof);
    const depIx = await program.methods
      .transactSpl(depProof as any, { extAmount: depositAmount, fee: new BN(0) }, enc1, enc2)
      .accountsPartial({
        treeAccount: splTreePDA,
        nullifier0: dn.nullifier0PDA,
        nullifier1: dn.nullifier1PDA,
        nullifier2: dn.nullifier2PDA,
        nullifier3: dn.nullifier3PDA,
        globalConfig: globalConfigPDA,
        signer: randomUser.publicKey,
        mint: splMint.publicKey,
        signerTokenAccount: userSplAta,
        recipient: treasury.publicKey,
        recipientTokenAccount: treasurySplAta,
        treeAta: splTreeAta,
        feeRecipientAta: treasurySplAta,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .instruction();
    const depTx = await createVersionedTransactionWithALT(
      provider.connection,
      randomUser.publicKey,
      [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }), depIx],
      altAddress
    );
    await sendAndConfirmVersionedTransaction(provider.connection, depTx, [randomUser]);
    splMerkleTree.insert(depCommits[0]);
    splMerkleTree.insert(depCommits[1]);

    // Withdraw 200 tokens with 0.5 token fee (0.25%)
    const recipient = Keypair.generate();
    const recipientAta = getAssociatedTokenAddressSync(splMint.publicKey, recipient.publicKey, false, TOKEN_PROGRAM_ID);
    const withdrawAmount = new BN(200_000_000);
    const withdrawFee = new BN(500_000);
    const change = depositAmount.sub(withdrawAmount).sub(withdrawFee);
    const wOut1 = new Utxo({ lightWasm, amount: change, keypair: utxoKeypair, index: 2, mintAddress: splMint.publicKey.toBase58() });
    const wOut2 = new Utxo({ lightWasm, amount: 0, keypair: utxoKeypair, index: 3, mintAddress: splMint.publicKey.toBase58() });
    const { proofArg: wProof } = await buildProof({
      tree: splMerkleTree,
      mint: splMint.publicKey,
      inputs: [out1, dummyIn2],
      outputs: [wOut1, wOut2],
      extAmount: withdrawAmount.neg(),
      fee: withdrawFee,
      recipient: recipientAta,
      feeRecipient: treasurySplAta,
      encryptedOutput1: enc1,
      encryptedOutput2: enc2,
    });
    const wn = findNullifierPDAs(program.programId, wProof);
    const wIx = await program.methods
      .transactSpl(wProof as any, { extAmount: withdrawAmount.neg(), fee: withdrawFee }, enc1, enc2)
      .accountsPartial({
        treeAccount: splTreePDA,
        nullifier0: wn.nullifier0PDA,
        nullifier1: wn.nullifier1PDA,
        nullifier2: wn.nullifier2PDA,
        nullifier3: wn.nullifier3PDA,
        globalConfig: globalConfigPDA,
        signer: relayer.publicKey,
        mint: splMint.publicKey,
        signerTokenAccount: relayer.publicKey,
        recipient: recipient.publicKey,
        recipientTokenAccount: recipientAta,
        treeAta: splTreeAta,
        feeRecipientAta: treasurySplAta,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .instruction();
    const wTx = await createVersionedTransactionWithALT(
      provider.connection,
      relayer.publicKey,
      [
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }),
        createAssociatedTokenAccountIdempotentInstruction(relayer.publicKey, recipientAta, recipient.publicKey, splMint.publicKey, TOKEN_PROGRAM_ID),
        createAssociatedTokenAccountIdempotentInstruction(relayer.publicKey, treasurySplAta, treasury.publicKey, splMint.publicKey, TOKEN_PROGRAM_ID),
        wIx,
      ],
      altAddress
    );
    await sendAndConfirmVersionedTransaction(provider.connection, wTx, [relayer]);

    const recAcc = await getAccount(provider.connection, recipientAta, undefined, TOKEN_PROGRAM_ID);
    const feeAcc = await getAccount(provider.connection, treasurySplAta, undefined, TOKEN_PROGRAM_ID);
    expect(recAcc.amount.toString()).to.equal(withdrawAmount.toString());
    expect(feeAcc.amount.toString()).to.equal(withdrawFee.toString());
  });

  it("enforces global_config.fee_recipient and per-tree min_withdrawal_fee on SOL transact", async () => {
    const utxoKeypair = UtxoKeypair.generateNew(lightWasm);
    const depAmount = new BN(LAMPORTS_PER_SOL); // 1 SOL
    const dummyIn1 = new Utxo({ lightWasm, amount: 0, keypair: utxoKeypair, mintAddress: SOL_ADDRESS.toBase58() });
    const dummyIn2 = new Utxo({ lightWasm, amount: 0, keypair: utxoKeypair, mintAddress: SOL_ADDRESS.toBase58() });
    const out1 = new Utxo({ lightWasm, amount: depAmount, keypair: utxoKeypair, index: 0, mintAddress: SOL_ADDRESS.toBase58() });
    const out2 = new Utxo({ lightWasm, amount: 0, keypair: utxoKeypair, index: 1, mintAddress: SOL_ADDRESS.toBase58() });
    const enc1 = Buffer.from("sol_dep1");
    const enc2 = Buffer.from("sol_dep2");

    // Deposit 1 SOL (fee_recipient_account must match treasury)
    const { proofArg: depProof, outputCommitments: depCommits } = await buildProof({
      tree: solMerkleTree,
      mint: SOL_ADDRESS,
      inputs: [dummyIn1, dummyIn2],
      outputs: [out1, out2],
      extAmount: depAmount,
      fee: new BN(0),
      recipient: treasury.publicKey,
      feeRecipient: treasury.publicKey,
      encryptedOutput1: enc1,
      encryptedOutput2: enc2,
    });
    const dn = findNullifierPDAs(program.programId, depProof);
    const depIx = await program.methods
      .transact(depProof as any, { extAmount: depAmount, fee: new BN(0) }, enc1, enc2)
      .accountsPartial({
        treeAccount: solTreePDA,
        nullifier0: dn.nullifier0PDA,
        nullifier1: dn.nullifier1PDA,
        nullifier2: dn.nullifier2PDA,
        nullifier3: dn.nullifier3PDA,
        treeTokenAccount: solTreeTokenPDA,
        globalConfig: globalConfigPDA,
        recipient: treasury.publicKey,
        feeRecipientAccount: treasury.publicKey,
        signer: randomUser.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .instruction();
    const depTx = await createVersionedTransactionWithALT(
      provider.connection,
      randomUser.publicKey,
      [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }), depIx],
      altAddress
    );
    await sendAndConfirmVersionedTransaction(provider.connection, depTx, [randomUser]);
    solMerkleTree.insert(depCommits[0]);
    solMerkleTree.insert(depCommits[1]);

    // Set SOL min_withdrawal_fee = 0.01 SOL
    const solMinFee = new BN(0.01 * LAMPORTS_PER_SOL);
    await program.methods
      .updateTreeConfig(null, null, solMinFee)
      .accountsPartial({
        treeAccount: solTreePDA,
        authority: admin.publicKey,
      })
      .signers([admin])
      .rpc();

    const freshRecipient = Keypair.generate();
    const withdrawAmount = new BN(0.2 * LAMPORTS_PER_SOL); // 0.25% = 0.0005 SOL < 0.01 SOL floor
    const change = depAmount.sub(withdrawAmount).sub(solMinFee);
    const wOut1 = new Utxo({ lightWasm, amount: change, keypair: utxoKeypair, index: 2, mintAddress: SOL_ADDRESS.toBase58() });
    const wOut2 = new Utxo({ lightWasm, amount: 0, keypair: utxoKeypair, index: 3, mintAddress: SOL_ADDRESS.toBase58() });

    const treasuryBefore = await provider.connection.getBalance(treasury.publicKey);
    const { proofArg: wProof } = await buildProof({
      tree: solMerkleTree,
      mint: SOL_ADDRESS,
      inputs: [out1, dummyIn2],
      outputs: [wOut1, wOut2],
      extAmount: withdrawAmount.neg(),
      fee: solMinFee,
      recipient: freshRecipient.publicKey,
      feeRecipient: treasury.publicKey,
      encryptedOutput1: enc1,
      encryptedOutput2: enc2,
    });
    const wn = findNullifierPDAs(program.programId, wProof);
    const wIx = await program.methods
      .transact(wProof as any, { extAmount: withdrawAmount.neg(), fee: solMinFee }, enc1, enc2)
      .accountsPartial({
        treeAccount: solTreePDA,
        nullifier0: wn.nullifier0PDA,
        nullifier1: wn.nullifier1PDA,
        nullifier2: wn.nullifier2PDA,
        nullifier3: wn.nullifier3PDA,
        treeTokenAccount: solTreeTokenPDA,
        globalConfig: globalConfigPDA,
        recipient: freshRecipient.publicKey,
        feeRecipientAccount: treasury.publicKey,
        signer: relayer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .instruction();
    const wTx = await createVersionedTransactionWithALT(
      provider.connection,
      relayer.publicKey,
      [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }), wIx],
      altAddress
    );
    await sendAndConfirmVersionedTransaction(provider.connection, wTx, [relayer]);

    const recipientBal = await provider.connection.getBalance(freshRecipient.publicKey);
    const treasuryAfter = await provider.connection.getBalance(treasury.publicKey);
    expect(recipientBal).to.equal(withdrawAmount.toNumber());
    expect(treasuryAfter - treasuryBefore).to.equal(solMinFee.toNumber());
  });
});
