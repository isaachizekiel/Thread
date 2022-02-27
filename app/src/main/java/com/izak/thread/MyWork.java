package com.izak.thread;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.security.auth.x500.X500Principal;

public class MyWork {
    private static final String TAG = "MyWork";
    public static final String KEY_ALIAS = "bt251";

    public static final String VALUE_SEPARATOR = "-";
    public static final String ISO_SIGN_ETB = "ETB";
    public static final float PER_BLOCK_REWARD = 0.003f;    ;

    private KeyStore ks;
    private File f, old;

    private final String p;

    private byte[] signature;
    private byte[] data;

    public MyWork(String path) {
        p = path;
    }

    public boolean Work() {
        try {
            createKeys();
        } catch (NoSuchProviderException
                | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException
                | CertificateException
                | KeyStoreException
                | IOException e) {
            e.printStackTrace();
        }

        File workingDir = new File(p);
        File [] listFiles = workingDir.listFiles();
        boolean done = false;

        if (listFiles == null || listFiles.length == 0) {
            Log.e(TAG, "init: files list is null for directory " +
                    workingDir.getAbsolutePath());
            return false;
        }

        for (File listFile : listFiles) {
            if (listFile.isFile()) {
                done = listFile.getName().endsWith(ISO_SIGN_ETB);
                if (done) {
                    f = listFile;
                    data = f.getName().getBytes(StandardCharsets.UTF_8);
                    Log.e(TAG, "init: Found" + f.getAbsolutePath() );
                    readTokenSig();
                    boolean verified = false;
                    try {
                        verified = verifyToken();
                    } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException
                            | IOException | UnrecoverableEntryException | InvalidKeyException
                            | SignatureException e) {
                        e.printStackTrace();
                    }
                    if (verified) {
                        boolean update = updateToken();
                        if (update) {
                            try {
                                signToken();
                                writeTokenSig();
                                deleteOldToken();
                            } catch (KeyStoreException | UnrecoverableEntryException
                                    | NoSuchAlgorithmException | InvalidKeyException
                                    | SignatureException | IOException | CertificateException e) {
                                e.printStackTrace();
                            }
                        }
                    } else {
                        Log.e(TAG, "Work: Signature not valid" );
                    }
                    return true;
                }
            }
        }

        /* Create new token */
        f = new File(workingDir + "/" + PER_BLOCK_REWARD + VALUE_SEPARATOR + ISO_SIGN_ETB);
        try {
            done = f.createNewFile();
            data = f.getName().getBytes(StandardCharsets.UTF_8);
            // sign and write the newly created token
            signToken();
            writeTokenSig();
        } catch (IOException | UnrecoverableEntryException | CertificateException
                | KeyStoreException | NoSuchAlgorithmException | SignatureException
                | InvalidKeyException e) {
            e.printStackTrace();
        }

        return done;
    }

    private boolean updateToken() {
        String [] token_parts = f.getName().split(VALUE_SEPARATOR);
        float value = Float.parseFloat(token_parts[0]);
        value += PER_BLOCK_REWARD;
        String new_token_value = String.format(java.util.Locale.US,"%.3f", value)
                + VALUE_SEPARATOR + ISO_SIGN_ETB;
        data = new_token_value.getBytes(StandardCharsets.UTF_8);
        Log.e(TAG, "updateToken: " + new_token_value);
        old = f;
        f = new File(p + "/" +  new_token_value);
        try {
            return f.createNewFile();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    private void writeTokenSig() {
        try {
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(signature);
            fos.close();
        } catch (Exception e) {
            Log.e(TAG, e.getMessage());
        }
    }

    private void readTokenSig() {
        int size = (int) f.length();
        signature = new byte[size];
        try {
            BufferedInputStream buf = new BufferedInputStream(new FileInputStream(f));
            int num = buf.read(signature, 0, signature.length);
            buf.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private boolean deleteOldToken() {
        if (old != null && old.isFile() && old.exists()) return old.delete();
        else return false;
    }

    private void createKeys() throws NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, KeyStoreException, CertificateException,
            IOException {
        ks = KeyStore.getInstance(SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
        ks.load(null);

        if (ks.containsAlias(KEY_ALIAS)) return;

        Log.e(TAG, "Generating new Keypair");

        Calendar start = new GregorianCalendar();
        Calendar end = new GregorianCalendar();
        end.add(Calendar.YEAR, 1);

        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(SecurityConstants.TYPE_RSA, SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
        AlgorithmParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setCertificateSubject(new X500Principal("CN=" + KEY_ALIAS))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setCertificateSerialNumber(BigInteger.valueOf(1337))
                .setCertificateNotBefore(start.getTime())
                .setCertificateNotAfter(end.getTime())
                .build();;

        kpGenerator.initialize(spec);

        KeyPair kp = kpGenerator.generateKeyPair();
        // END_INCLUDE(create_spec)
        Log.d(TAG, "Public Key is: " + kp.getPublic().toString());
    }

    private void signToken() throws KeyStoreException, UnrecoverableEntryException,
            NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException,
            CertificateException {
        // BEGIN_INCLUDE(sign_load_keystore)
        ks = KeyStore.getInstance(SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);

        // Weird artifact of Java API.  If you don't have an InputStream to load, you still need
        // to call "load", or it'll crash.
        ks.load(null);

        // Load the key pair from the Android Key Store
        KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);

        /* If the entry is null, keys were never stored under this alias.
         * Debug steps in this situation would be:
         * -Check the list of aliases by iterating over Keystore.aliases(), be sure the alias
         *   exists.
         * -If that's empty, verify they were both stored and pulled from the same keystore
         *   "AndroidKeyStore"
         */
        if (entry == null) {
            Log.w(TAG, "No key found under alias: " + KEY_ALIAS);
            Log.w(TAG, "Exiting signData()...");
            return;
        }

        /* If entry is not a KeyStore.PrivateKeyEntry, it might have gotten stored in a previous
         * iteration of your application that was using some other mechanism, or been overwritten
         * by something else using the same keystore with the same alias.
         * You can determine the type using entry.getClass() and debug from there.
         */
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w(TAG, "Not an instance of a PrivateKeyEntry");
            Log.w(TAG, "Exiting signData()...");
            return;
        }
        // END_INCLUDE(sign_data)

        // BEGIN_INCLUDE(sign_create_signature)
        // This class doesn't actually represent the signature,
        // just the engine for creating/verifying signatures, using
        // the specified algorithm.
        Signature s = Signature.getInstance(SecurityConstants.SIGNATURE_SHA256withRSA);

        // Initialize Signature using specified private key
        s.initSign(((KeyStore.PrivateKeyEntry) entry).getPrivateKey());

        // Sign the data, store the result as a Base64 encoded String.
        s.update(data);
        signature = s.sign();

    }

    private boolean verifyToken() throws KeyStoreException,
            CertificateException, NoSuchAlgorithmException, IOException,
            UnrecoverableEntryException, InvalidKeyException, SignatureException {
        // Make sure the signature string exists.  If not, bail out, nothing to do.
        if (data == null) {
            Log.e(TAG, "verifyToken: Data is null");
            return false;
        }

        ks = KeyStore.getInstance("AndroidKeyStore");

        // Weird artifact of Java API.  If you don't have an InputStream to load, you still need
        // to call "load", or it'll crash.
        ks.load(null);

        // Load the key pair from the Android Key Store
        KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);

        if (entry == null) {
            Log.e(TAG, "verifyToken: No key found under alias: " + KEY_ALIAS);
            return false;
        }

        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.e(TAG, "verifyToken: Not an instance of a PrivateKeyEntry");
            return false;
        }

        // This class doesn't actually represent the signature,
        // just the engine for creating/verifying signatures, using
        // the specified algorithm.
        Signature s = Signature.getInstance(SecurityConstants.SIGNATURE_SHA256withRSA);

        s.initVerify(((KeyStore.PrivateKeyEntry) entry).getCertificate());
        s.update(data);
        return s.verify(signature);
    }

}
