<?php

use phpseclib\Crypt\RSA;

class License
{
    // Private key for RSA signature
    private $_pk;

    /**
     * License constructor.
     *
     * @param array $config
     *
     * @throws ConflictHttpException
     */
    public function __construct(array $config = [])
    {
        if (file_exists("keys/license.keys")) {
            $this->_pk = file_get_contents('keys/license.keys');
        } else {
            throw new ConflictHttpException;
        }
    }

    /**
     * This function sets the received data to the private data attribute.
     *
     * @param $data String value in JSON format
     */
    public function setData($data)
    {
        $this->_data = json_decode($data);
    }

    /**
     * This function generates a RSA-1024 signature of
     * a given message with private key.
     *
     * @param $message String that has to be signed.
     *
     * @return string Returns the calculated signature as Base64.
     */
    private function sign_with_rsa($message)
    {
        // New RSA object gets the private key for signing the SHA-512 hashed XML content.
        $rsa = new RSA();
        //$rsa->setPrivateKeyFormat($rsa::PRIVATE_FORMAT_XML);
        $rsa->loadKey($this->_pk, $rsa::PRIVATE_FORMAT_XML); // private key

        // The default mode is PSS. If it is desirable to use
        // the Public-Key Cryptography Standard 1,
        // simply use $rsa->setSignatureMode($rsa::SIGNATURE_PKCS1);
        $rsa->setSignatureMode($rsa::SIGNATURE_PKCS1);
        $rsa->setHash("sha512");
        $signature = $rsa->sign($message);

        // Base64 encryption of signature
        $signature = base64_encode($signature);

        return $signature;
    }

    public function verify_license($signature, $message)
    {
        $signature = base64_decode($signature);
        $rsa = new RSA();
        $rsa->setHash("sha512");
        $rsa->setSignatureMode($rsa::SIGNATURE_PKCS1);
        $rsa->loadKey($this->_pk); // Load private key to RSA object.
        $rsa->setPublicKey(); // Set a public key for validation
        $rsa->loadKey($rsa->getPublicKey()); // Load public key to RSA object.
        return $rsa->verify($message, $signature); // Verify and return either 1 or 0
    }
}
