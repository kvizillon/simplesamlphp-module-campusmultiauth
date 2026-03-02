<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth;

class Fingerprinting
{
    /**
     * Hash algorithm used for browser fingerprint.
     */
    private const HASH_ALG = 'sha512';

    /**
     * Class prefix for fingerprint bits.
     */
    private const CLASS_PREFIX = '\\SimpleSAML\\Module\\campusmultiauth\\Fingerprint\\';

    /**
     * Bits of information used for the fingerprint.
     */
    private const BITS = [
        'Header\\Accept',
        'Header\\AcceptCharset',
        'Header\\AcceptEncoding',
        'Header\\AcceptLanguage',
        'Header\\Connection',
        'Header\\DNT',
        'Header\\XRequestedWith',
        'Header\\UpgradeInsecureRequests',
        'Browser\\Name',
        'Browser\\Platform',
    ];

    public static function getBrowserFingerprint()
    {
        $info = [];
        foreach (self::BITS as $bit) {
            $className = self::CLASS_PREFIX . $bit;
            $info[$bit] = (new $className())->getValue();
        }

        return hash(self::HASH_ALG, serialize($info));
    }
}
