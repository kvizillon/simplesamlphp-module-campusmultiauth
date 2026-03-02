<?php

namespace SimpleSAML\Module\campusmultiauth\Auth\Process;

use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module\campusmultiauth\Constants;
use SimpleSAML\Module\campusmultiauth\Fingerprinting;
use SimpleSAML\Module\campusmultiauth\Utils;
use SimpleSAML\Module\core\Stats\Output\Log;
use SimpleSAML\Utils\HTTP;

/**
 * Inspired by the Facebook class.
 *
 * @see https://github.com/simplesamlphp/simplesamlphp/blob/simplesamlphp-1.14/modules/authfacebook/lib/Facebook.php
 */
class RememberMe extends ProcessingFilter
{
    /**
     * Name of the GET parameter to clear username.
     */
    public const CLEAR_USERNAME_PARAM = 'init';

    /**
     * Value of the GET parameter to clear username.
     */
    public const CLEAR_USERNAME_VALUE = 'true';

    /**
     * The lifetime of the cookie.
     */
    private const COOKIE_LIFETIME = 31536000;

    /**
     * The secure parameter of the cookie.
     */
    private const COOKIE_SECURE = true;

    /**
     * The http_only parameter of the cookie.
     */
    private const COOKIE_HTTPONLY = true;

    /**
     * Default cookie path.
     */
    private const DEFAULT_COOKIE_PATH = '/';

    /**
     * \SimpleSAML\Module\campusmultiauth\Security\Cipher implementation.
     */
    private $cipher;

    /**
     * Whether to store security image into the cookie or leave it to the login screen to fetch the fresh image.
     */
    private $showFreshImage;

    /**
     * \SimpleSAML\Module\campusmultiauth\Data\Storage implementation.
     */
    private $storage;

    /**
     * Cookie path.
     */
    private $cookiePath;

    /**
     * Cookie SameSite.
     */
    private $cookieSameSite;

    /**
     * Name of the cookie.
     */
    private $cookieName;

    /**
     * Name of the don't remember me cookie.
     */
    private $dontCookieName;

    /**
     * Name of the name attribute.
     */
    private $nameAttr;

    /**
     * The constructor.
     *
     * @override
     *
     * @param mixed|null $config
     * @param mixed|null $reserved
     */
    public function __construct($config = null, $reserved = null)
    {
        if ($config) {
            parent::__construct($config, $reserved);
        }

        $configuration = Configuration::getOptionalConfig('module_campusmultiauth.php')
            ->getConfigItem('remember_me', []);

        $imagesConfiguration = $configuration->getConfigItem('security_images', []);

        $this->showFreshImage = $imagesConfiguration->getBoolean('showFreshImage', false);

        $this->cookiePath = $configuration->getString('security.cookie.path', self::DEFAULT_COOKIE_PATH);
        $this->cookieSameSite = $configuration->getString('security.cookie.samesite', null);
        $this->cookieName = $configuration->getString('cookieName', 'campus_userinfo');
        $this->dontCookieName = $configuration->getString('dontCookieName', 'campus_dont_remember');
        $this->nameAttr = $configuration->getString('nameAttr', 'displayName');
    }

    /**
     * Get user info from a cookie.
     */
    public function getUserInfo(bool $updateCounter = true)
    {
        // cookie is present
        if (!isset($_COOKIE[$this->cookieName])) {
            return false;
        }

        // cookie is valid
        try {
            $data = json_decode($this->getCipher()->decrypt($_COOKIE[$this->cookieName]), true);
        } catch (\Exception $e) {
            $this->deleteCookie();

            return false;
        }

        // browser match
        if ($data['browser'] !== $this->getBrowserFingerprint()) {
            Logger::warning(sprintf('campusmultiauth: Cookie browser mismatch with id %d', $data['id']));
            $this->deleteCookie();

            return false;
        }

        // counter match
        $storage = $this->getStorage();
        if ($storage->getCookieCounter($data['username'], $data['id']) !== $data['counter']) {
            // replayed cookie
            Logger::warning(
                sprintf('campusmultiauth: Replayed cookie with id %d and counter %d', $data['id'], $data['counter'])
            );
            $this->deleteCookie();

            return false;
        }

        if ($updateCounter) {
            // increment counter
            $storage->increaseCookieCounter($data['username'], $data['id']);
            ++$data['counter'];

            // update cookie
            $this->setCookie($data);
        }

        return $data;
    }

    /**
     * Save user info in a cookie.
     */
    public function setUserInfo(string $username, string $name)
    {
        $browser = $this->getBrowserFingerprint();

        $userInfo = $this->getUserInfo(false);
        $id = null;
        $counter = 0;
        $storage = $this->getStorage();
        if ($userInfo !== false && $userInfo['username'] === $username && $userInfo['browser'] === $browser) {
            $id = $userInfo['id'];
            $counter = $userInfo['counter'];
        }
        $id = $storage->increaseCookieCounter($username, $id);
        if ($id === null) {
            Logger::error('Could not insert cookie counter into database.');
            $this->deleteCookie();

            return;
        }
        ++$counter;

        $payload = [
            'username' => $username,
            'name' => $name,
            'browser' => $browser,
            'id' => $id,
            'counter' => $counter,
        ];

        Logger::debug('Setting user info cookie: ' . print_r($payload, true));

        if (!$this->showFreshImage) {
            $payload['security_image'] = Utils::getSecurityImageOfUser($username);
            $payload['alternative_text'] = Utils::getAlternativeTextOfUser($username);
        }

        $this->setCookie($payload);
    }

    /**
     * Delete the cookie.
     */
    public function deleteCookie()
    {
        $this->deleteACookie($this->cookieName);
    }

    public function getDontCookieName()
    {
        return $this->dontCookieName;
    }

    /**
     * The constructor.
     *
     * @override
     *
     * @param mixed $request
     */
    public function process(array &$state): void
    {
        $uid_attribute = Configuration::getOptionalConfig('module_campusmultiauth.php')
            ->getConfigItem('remember_me', [])
            ->getString('uid_attribute', 'uid');

        if (
            !empty($request['RememberMe'])
            && !empty($request['Attributes'][$uid_attribute])
            && !empty($request['Attributes'][$this->nameAttr][0])
        ) {
            $uid = $request['Attributes'][$uid_attribute][0];
            $name = $request['Attributes'][$this->nameAttr][0];
            $this->setUserInfo($uid, $name);
            $this->deleteACookie($this->dontCookieName);
        }

        if (!empty($request['DontRememberMe'])) {
            $this->setACookie($this->dontCookieName, 'Yes');
            $this->deleteCookie();
        }
    }

    /**
     * Get hyperlink for the "this is not my username" button.
     *
     * @param mixed $authState
     */
    public static function getOtherUsernameLink($authState)
    {
        $link = (new HTTP())->getSelfURL();
        $link = (new HTTP())->addURLParameters($link, [
            self::CLEAR_USERNAME_PARAM => self::CLEAR_USERNAME_VALUE,
        ]);
    
        return (new HTTP())->addURLParameters($link, [
            'AuthState' => $authState,
        ]);
    }
    
    /**
     * Get info about the browser, which should not change too often.
     */
    protected function getBrowserFingerprint()
    {
        return Fingerprinting::getBrowserFingerprint();
    }

    private function getStorage()
    {
        if (!$this->storage) {
            $this->storage = Utils::getInterfaceInstance(
                'SimpleSAML\\Module\\campusmultiauth\\Data\\Storage',
                'storageClass',
                'SimpleSAML\\Module\\campusmultiauth\\Data\\DatabaseStorage'
            );
        }

        return $this->storage;
    }

    private function setCookie(array $data)
    {
        $cookie_value = $this->getCipher()->encrypt(json_encode($data));
        $this->setACookie($this->cookieName, $cookie_value);

        if ($this->cookiePath !== '/') {
            HTTP::setCookie($this->cookieName, null, [
                'secure' => self::COOKIE_SECURE,
                'httponly' => self::COOKIE_HTTPONLY,
                'path' => '/',
                'samesite' => $this->cookieSameSite,
            ], false);
        }
        if ($this->cookiePath !== '/simplesaml/module.php/core') {
            HTTP::setCookie($this->cookieName, null, [
                'secure' => self::COOKIE_SECURE,
                'httponly' => self::COOKIE_HTTPONLY,
                'path' => '/simplesaml/module.php/core',
                'samesite' => $this->cookieSameSite,
            ], false);
        }
    }

    private function setACookie(string $name, string $value)
    {
        $_COOKIE[$name] = $value;

        HTTP::setCookie($name, $value, [
            'lifetime' => self::COOKIE_LIFETIME,
            'secure' => self::COOKIE_SECURE,
            'httponly' => self::COOKIE_HTTPONLY,
            'path' => $this->cookiePath,
            'samesite' => $this->cookieSameSite,
        ], false);
    }

    /**
     * Delete a cookie.
     */
    private function deleteACookie(string $name)
    {
        unset($_COOKIE[$name]);

        HTTP::setCookie($name, null, [
            'secure' => self::COOKIE_SECURE,
            'httponly' => self::COOKIE_HTTPONLY,
            'path' => $this->cookiePath,
            'samesite' => $this->cookieSameSite,
        ], false);

        if ($this->cookiePath !== '/') {
            HTTP::setCookie($name, null, [
                'secure' => self::COOKIE_SECURE,
                'httponly' => self::COOKIE_HTTPONLY,
                'path' => '/',
                'samesite' => $this->cookieSameSite,
            ], false);
        }
        if ($this->cookiePath !== '/simplesaml/module.php/core') {
            HTTP::setCookie($name, null, [
                'secure' => self::COOKIE_SECURE,
                'httponly' => self::COOKIE_HTTPONLY,
                'path' => '/simplesaml/module.php/core',
                'samesite' => $this->cookieSameSite,
            ], false);
        }
    }

    private function getCipher()
    {
        if (empty($this->cipher)) {
            $this->cipher = Utils::getInterfaceInstance(
                'SimpleSAML\\Module\\campusmultiauth\\Security\\Cipher',
                'cipherClass',
                'SimpleSAML\\Module\\campusmultiauth\\Security\\JWTCipher'
            );
        }

        return $this->cipher;
    }
}
