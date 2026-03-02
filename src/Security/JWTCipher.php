<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth\Security;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\JSONFlattenedSerializer as JWEJSONFlattenedSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\NestedToken\NestedTokenBuilder;
use Jose\Component\NestedToken\NestedTokenLoader;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer as JWSJSONFlattenedSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;

class JWTCipher implements Cipher
{
    private $builder;

    private $loader;

    private $signature_key;

    private $signature_keyset;

    private $encryption_key;

    private $encryption_keyset;

    private $signature_algorithm;

    private $encryption_algorithm;

    private $keywrap_algorithm;

    /**
     * @override
     */
    public function __construct()
    {
        $moduleConfig = Configuration::getOptionalConfig('module_campusmultiauth.php')
            ->getConfigItem('remember_me', []);

        $signatureKey = $moduleConfig->getArray('signature_key');
        $this->signature_key = new JWK($signatureKey);
        $this->signature_keyset = JWKSet::createFromKeyData([
            'keys' => [$signatureKey],
        ]);
        $encryptionKey = $moduleConfig->getArray('encryption_key');
        $this->encryption_key = new JWK($encryptionKey);
        $this->encryption_keyset = JWKSet::createFromKeyData([
            'keys' => [$encryptionKey],
        ]);
        $this->signature_algorithm = self::getAlgorithm(
            'Signature\\Algorithm',
            $moduleConfig->getString('signature_algorithm', 'HS512')
        );
        $this->encryption_algorithm = self::getAlgorithm(
            'Encryption\\Algorithm\\ContentEncryption',
            $moduleConfig->getString('encryption_algorithm', 'A256GCM')
        );
        $this->keywrap_algorithm = self::getAlgorithm(
            'Encryption\\Algorithm\\KeyEncryption',
            $moduleConfig->getString('keywrap_algorithm', 'A256GCMKW')
        );
    }

    /**
     * @override
     */
    public function encrypt(string $data)
    {
        if (!$this->builder) {
            $this->builder = $this->getBuilder();
        }

        $token = $this->builder->create(
        // The payload to protect
            $data,
            // A list of signatures
            [[
                'key' => $this->signature_key,
                'protected_header' => [
                    'alg' => $this->signature_algorithm->name(),
                ],
            ]],
            // The serialization mode for the JWS
            'jws_json_flattened',
            // The shared protected header
            [
                'alg' => $this->keywrap_algorithm->name(),
                'enc' => $this->encryption_algorithm->name(),
            ],
            // The shared unprotected header
            [],
            // A list of recipients
            [[
                'key' => $this->encryption_key,
                'header' => [],
            ]],
            // The serialization mode for the JWE.
            'jwe_json_flattened'
        );

        Logger::debug(sprintf('Encrypted JWT: %s', $token));

        return $token;
    }

    /**
     * @override
     */
    public function decrypt(string $data)
    {
        if (!$this->loader) {
            $this->loader = $this->getLoader();
        }

        $jws = $this->loader->load($data, $this->encryption_keyset, $this->signature_keyset);

        $payload = $jws->getPayload();

        Logger::debug(sprintf('Decrypted JWT: %s', $payload));

        return $payload;
    }

    private static function getAlgorithm($path, $className)
    {
        $classPath = sprintf('Jose\\Component\\%s\\%s', $path, $className);
        if (!class_exists($classPath)) {
            throw new \Exception('Invalid algorithm specified: ' . $classPath);
        }

        return new $classPath();
    }

    /**
     * @return JWSBuilder
     */
    private function getJWSBuilder()
    {
        $algorithmManager = new AlgorithmManager([$this->signature_algorithm]);

        return new JWSBuilder($algorithmManager);
    }

    /**
     * @return JWEBuilder
     */
    private function getJWEBuilder()
    {
        $keyEncryptionAlgorithmManager = new AlgorithmManager([$this->keywrap_algorithm]);

        $contentEncryptionAlgorithmManager = new AlgorithmManager([$this->encryption_algorithm]);

        $compressionMethodManager = new CompressionMethodManager([new Deflate()]);

        return new JWEBuilder(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );
    }

    /**
     * @return NestedTokenBuilder
     */
    private function getBuilder()
    {
        $jweBuilder = $this->getJWEBuilder();
        $jwsBuilder = $this->getJWSBuilder();

        $jweSerializerManager = new JWESerializerManager([new JWEJSONFlattenedSerializer()]);
        $jwsSerializerManager = new JWSSerializerManager([new JWSJSONFlattenedSerializer()]);

        return new NestedTokenBuilder($jweBuilder, $jweSerializerManager, $jwsBuilder, $jwsSerializerManager);
    }

    /**
     * @return JWELoader
     */
    private function getJWELoader()
    {
        $keyEncryptionAlgorithmManager = new AlgorithmManager([$this->keywrap_algorithm]);

        $contentEncryptionAlgorithmManager = new AlgorithmManager([$this->encryption_algorithm]);

        $compressionMethodManager = new CompressionMethodManager([new Deflate()]);

        $jweDecrypter = new JWEDecrypter(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );

        $serializerManager = new JWESerializerManager([new JWEJSONFlattenedSerializer()]);

        return new JWELoader($serializerManager, $jweDecrypter, null);
    }

    /**
     * @return JWSLoader
     */
    private function getJWSLoader()
    {
        $algorithmManager = new AlgorithmManager([$this->signature_algorithm]);

        $jwsVerifier = new JWSVerifier($algorithmManager);

        $serializerManager = new JWSSerializerManager([new JWSJSONFlattenedSerializer()]);

        return new JWSLoader($serializerManager, $jwsVerifier, null);
    }

    /**
     * @return NestedTokenLoader
     */
    private function getLoader()
    {
        $jweLoader = $this->getJWELoader();
        $jwsLoader = $this->getJWSLoader();

        return new NestedTokenLoader($jweLoader, $jwsLoader);
    }
}
