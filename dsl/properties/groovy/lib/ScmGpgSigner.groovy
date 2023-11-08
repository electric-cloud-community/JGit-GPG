import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import org.eclipse.jgit.api.errors.JGitInternalException
import org.eclipse.jgit.internal.JGitText
import org.eclipse.jgit.lib.CommitBuilder
import org.eclipse.jgit.lib.GpgSignature
import org.eclipse.jgit.lib.GpgSigner
import org.eclipse.jgit.lib.PersonIdent
import org.eclipse.jgit.transport.CredentialsProvider

class ScmGpgSigner extends GpgSigner {

    private final PGPKeyPair keyPair;

    ScmGpgSigner(PGPKeyPair keyPair) {
        this.keyPair = keyPair;
    }

    @Override
    public boolean canLocateSigningKey(String gpgSigningKey, PersonIdent committer, CredentialsProvider credentialsProvider) {
        return true;
    }

    @Override
    public void sign(CommitBuilder commit, String gpgSigningKey,
                     PersonIdent committer, CredentialsProvider credentialsProvider) {
        try {
            if (keyPair == null) {
                throw new JGitInternalException(JGitText.get().unableToSignCommitNoSecretKey);
            }

            PGPPrivateKey privateKey = keyPair.getPrivateKey();

            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(
                    keyPair.getPublicKey().getAlgorithm(),
                    HashAlgorithmTags.SHA256).setProvider(BouncyCastleProvider.PROVIDER_NAME)
            );
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey)

            ByteArrayOutputStream buffer = new ByteArrayOutputStream()
            BCPGOutputStream out = null
            try {
                out = new BCPGOutputStream(new ArmoredOutputStream(buffer))
                signatureGenerator.update(commit.build());
                signatureGenerator.generate().encode(out);
            } catch (Exception e) {
                throw e
            }
            finally {
                if (out != null) {
                    out.close()
                }
            }
            commit.setGpgSignature(new GpgSignature(buffer.toByteArray()));
        } catch (PGPException | IOException e) {
            throw new JGitInternalException(e.getMessage(), e)
        }
    }
}