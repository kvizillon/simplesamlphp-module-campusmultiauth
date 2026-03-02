<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth;

use SimpleSAML\Configuration;

class Utils
{
    public static function getInterfaceInstance($interface, $optionName, $defaultClassPath)
    {
        $config = Configuration::getOptionalConfig('module_campusmultiauth.php')->getConfigItem('remember_me', []);
        $classPath = $config->getString($optionName, $defaultClassPath);
        if (!in_array($interface, class_implements($classPath), true)) {
            throw new \Exception('Invalid ' . $optionName . ' specified: ' . $classPath);
        }

        return new $classPath();
    }

    public static function getSecurityImageOfUser($username)
    {
        $storage = self::getInterfaceInstance(
            'SimpleSAML\\Module\\campusmultiauth\\Data\\Storage',
            'storageClass',
            'SimpleSAML\\Module\\campusmultiauth\\Data\\DatabaseStorage'
        );

        return $storage->getSecurityImageOfUser($username);
    }

    public static function getAlternativeTextOfUser($username)
    {
        $storage = self::getInterfaceInstance(
            'SimpleSAML\\Module\\campusmultiauth\\Data\\Storage',
            'storageClass',
            'SimpleSAML\\Module\\campusmultiauth\\Data\\DatabaseStorage'
        );

        return $storage->getAlternativeTextOfUser($username);
    }
}
