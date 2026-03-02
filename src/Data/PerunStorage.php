<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth\Data;

use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module\ldap\Auth\Ldap;
use SimpleSAML\Module\campusmultiauth\Constants;

/**
 * Implementation of Storage using Perun LDAP and Database.
 */
class PerunStorage extends DatabaseStorage
{
    /**
     * Configuration.
     */
    private $config;

    /**
     * LDAP instance.
     */
    private $ldap;

    /**
     * @override
     */
    public function __construct()
    {
        parent::__construct();
        $this->config = Configuration::getOptionalConfig('module_campusmultiauth.php')
            ->getConfigItem('remember_me', [])
            ->getConfigItem('security_images', [])
            ->getConfigItem('pictureStorage', []);

        $hostname = $this->config->getString('ldap.hostname');
        $port = $this->config->getInteger('ldap.port', 389);
        $enable_tls = $this->config->getBoolean('ldap.enable_tls', false);
        $debug = $this->config->getBoolean('ldap.debug', false);
        $referrals = $this->config->getBoolean('ldap.referrals', true);
        $timeout = $this->config->getInteger('ldap.timeout', 0);
        $username = $this->config->getString('ldap.username', null);
        $password = $this->config->getString('ldap.password', null);

        try {
            $this->ldap = new Ldap($hostname, $enable_tls, $debug, $timeout, $port, $referrals);
        } catch (\Exception $e) {
            // Added this warning in case $this->getLdap() fails
            Logger::warning('PerunStorage: LDAP exception ' . $e);

            return;
        }
        $this->ldap->bind($username, $password);
    }

    /**
     * @override
     */
    public function getSecurityImageOfUser(string $uid): ?string
    {
        $attribute = $this->config->getString('attribute', null);
        return $attribute === null ? null : $this->getSecurityAttributeOfUser($uid, $attribute);
    }

    /**
     * @override
     */
    public function getAlternativeTextOfUser(string $uid): ?string
    {
        $attribute = $this->config->getString('alternative_text_attribute', null);
        return $attribute === null ? null : $this->getSecurityAttributeOfUser($uid, $attribute);
    }

    private function getSecurityAttributeOfUser(string $uid, string $attribute)
    {
        $base = $this->config->getString('ldap.basedn');
        $filter = $this->config->getString('search.filter');
        $filter = str_replace('%uid%', $uid, $filter);

        try {
            $entries = $this->ldap->searchformultiple([$base], $filter, [$attribute], [], true, false);
        } catch (\Exception $e) {
            $entries = [];
        }
        if (count($entries) < 1 || empty($entries[0][$attribute])) {
            return null;
        }

        return $entries[0][$attribute][0];
    }
}
