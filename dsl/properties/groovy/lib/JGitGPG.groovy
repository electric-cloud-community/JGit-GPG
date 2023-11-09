import com.cloudbees.flowpdf.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import org.eclipse.jgit.api.CreateBranchCommand
import org.eclipse.jgit.api.Git
import org.eclipse.jgit.api.errors.RefAlreadyExistsException
import org.eclipse.jgit.lib.GpgSigner
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider

import java.security.Security

/**
 * JGitGPG
 */
class JGitGPG extends FlowPlugin {

    @Override
    Map<String, Object> pluginInfo() {
        return [
            pluginName         : '@PLUGIN_KEY@',
            pluginVersion      : '@PLUGIN_VERSION@',
            configFields       : ['config'],
            configLocations    : ['ec_plugin_cfgs'],
            defaultConfigValues: [:]
        ]
    }

    /** This is a special method for checking connection during configuration creation
     */
    def checkConnection(StepParameters p, StepResult sr) {
        // Use this pre-defined method to check connection parameters
        try {
            // Put some checks here
            initBouncyCastle()
            def keyPair = extractPrivateKey()
            log.info "Read key pair successfully: key ID ${Long.toHexString(keyPair.keyID).toUpperCase()}"
            // assert config.getRequiredCredential("credential").secretValue == "secret"
        } catch (Throwable e) {
            // Set this property to show the error in the UI
            sr.setOutcomeProperty("/myJob/configError", e.message + System.lineSeparator() + "Please change the code of checkConnection method to incorporate your own connection checking logic")
            sr.apply()
            throw e
        }
    }

    // === check connection ends ===

    /**
     * commitWithSignature - Commit with signature/Commit with signature
     * Add your code into this method and it will be called when the step runs
     * @param config (required: true)
     * @param repoPath (required: true)
     * @param files (required: true)
     * @param push (required: )

     */
    def commitWithSignature(StepParameters p, StepResult sr) {

        initBouncyCastle()
        // Use this parameters wrapper for convenient access to your parameters
        CommitWithSignatureParameters sp = CommitWithSignatureParameters.initParameters(p)
        PGPKeyPair pair = extractPrivateKey()

        Git git = Git.init().setDirectory(new File(sp.repoPath)).call()

        if (sp.branch) {
            try {
                git.checkout().setCreateBranch(true).setName(sp.branch).call()
            } catch (RefAlreadyExistsException e) {
                git.checkout().setName(sp.branch).call()
            }

        }

        def files = sp.files.split(/\n+/)
        def addCommand = git.add()
        files.each {
            addCommand.addFilepattern(it)
            log.info "Adding file ${it}"
        }
        addCommand.call()

        GpgSigner signer = new ScmGpgSigner(pair)
        GpgSigner.setDefault(signer)

        def userIds = pair.getPublicKey().getUserIDs().next()
        def ids = userIds.split(/<|>/)
        def name = ids.first()
        def email = ids.last()

        log.info "Using key ID: email ${email} and user name ${name}"

        def revCommit = git.commit()
            .setCommitter(name, email)
            .setMessage(sp.commitMessage ?: 'Signed commit').setSign(true).call()
        log.info "Commit id: ${revCommit.getId()}"

        def signature = revCommit.getRawGpgSignature().encodeBase64().toString()
        log.info "GPG signature: ${signature}"


        if (sp.push) {
            def credential = context.configValues.getCredential('credential')
            def remoteName = sp.remote ?: git.repository.getRemoteNames().first()
            log.info "Pushing data to the remote $remoteName"
            def pushRes = git.push().setRemote(remoteName).setCredentialsProvider(
                new UsernamePasswordCredentialsProvider(credential.userName, credential.secretValue)
            ).call()

            pushRes.each {
                it.remoteUpdates.each { update ->
                    log.info "Remote name ${update.remoteName}"
                    log.info "Message: ${update.message}"
                }
            }
        }
    }


    PGPKeyPair extractPrivateKey() {
        def keyWithArmor = context.configValues.getRequiredCredential('gpg_credential')?.secretValue
        def bytes = keyWithArmor.getBytes("US-ASCII")
        InputStream raw = new ByteArrayInputStream(bytes)
        InputStream decoded = PGPUtil.getDecoderStream(raw)
        def fingerprintCalculator = new BcKeyFingerprintCalculator()
        PGPSecretKeyRing keyRing = new PGPSecretKeyRing(decoded, fingerprintCalculator)
        keyRing.secretKeys.each {
            def keyId = Long.toHexString(it.keyID).toUpperCase()
            log.info "Found key ${keyId}"
            log.info it.getUserIDs().join(", ")
            log.info '----------'
        }

        def secretValue = context.configValues.getCredential('gpg_passphrase_credential')?.secretValue
        def privateKey = extractPrivateKey(keyRing.getSecretKey(), secretValue.toCharArray())

        PGPKeyPair pair = new PGPKeyPair(keyRing.publicKey, privateKey)
        return pair
    }

    // === step ends ===

    static PGPPrivateKey extractPrivateKey(PGPSecretKey encryptedKey, final char[] passphrase) throws PGPException {
        PGPDigestCalculatorProvider calcProvider = new JcaPGPDigestCalculatorProviderBuilder()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build()

        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder(
            calcProvider).setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(passphrase)

        return encryptedKey.extractPrivateKey(decryptor)
    }


    static initBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider())
        }
    }


}