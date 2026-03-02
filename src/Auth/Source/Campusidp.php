<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth\Auth\Source;

use Exception;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth;
use SimpleSAML\Auth\Source;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Error\UnserializableException;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module;
use SimpleSAML\Module\core\Auth\UserPassBase;
use SimpleSAML\Module\ldap\Auth\Ldap;
use SimpleSAML\Session;
use SimpleSAML\Utils\HTTP;
use Transliterator;

/**
 * Authentication source that allows users to choose between a username/password
 * login and an external SAML/SP source on a single login page.
 *
 * This module also supports AARC IdP hinting and advanced metadata filtering.
 *
 * @package SimpleSAML\Module\campusmultiauth\Auth\Source
 */
class Campusidp extends Source
{
    // State and session keys
    public const string AUTHID = '\SimpleSAML\Module\campusidp\Auth\Source\Campusidp.AuthId';
    public const string STAGEID_USERPASS = '\SimpleSAML\Module\core\Auth\UserPassBase.state';
    public const string SOURCESID = '\SimpleSAML\Module\campusidp\Auth\Source\Campusidp.SourceId';
    public const string SESSION_SOURCE = 'campusmultiauth:selectedSource';
    public const string USER_PASS_SOURCE_NAME = 'userPassSourceName';
    public const string SP_SOURCE_NAME = 'spSourceName';

    // Cookie related constants
    public const string COOKIE_PREFIX = 'campusidp_';
    public const string COOKIE_PREVIOUS_IDPS = 'previous_idps';
    private const int COOKIE_LIFETIME = 7776000; // 90 days in seconds

    // IdP hinting constants
    public const string IDPHINT = 'idphint';
    public const string AARC_IDP_HINT = 'aarc_idp_hint';
    public const string AARC_DISCOVERY_HINT = 'aarc_discovery_hint';
    public const string AARC_DISCOVERY_HINT_URI = 'aarc_discovery_hint_uri';

    // Metadata filtering constants
    public const string INCLUDE = 'include';
    public const string EXCLUDE = 'exclude';
    public const string ALL_OF = 'all_of';
    public const string ANY_OF = 'any_of';
    public const string ENTITY_CATEGORY = 'entity_category';
    public const string ASSURANCE_CERTIFICATION = 'assurance_certification';
    public const string REGISTRATION_AUTHORITY = 'registration_authority';
    public const string ENTITYID = 'entityid';
    public const string CONTAINS = 'contains';
    public const string EQUALS = 'equals';
    public const string MATCHES = 'matches';

    private const string ENTITY_CATEGORY_ATTR_NAME = 'http://macedir.org/entity-category';
    private const string ASSURANCE_CERTIFICATION_ATTR_NAME = 'urn:oasis:names:tc:SAML:attribute:assurance-certification';
    public const int IDP_HINT_BUTTONS_LIMIT = 5;

    /** @var array<int, array{source: string, AuthnContextClassRef: array}> */
    private array $sources;

    private string $userPassSourceName;
    private string $spSourceName;

    /**
     * Constructor for this authentication source.
     *
     * @param array $info Information about this authentication source.
     * @param array $config Configuration for this authentication source.
     */
    public function __construct(array $info, array $config)
    {
        parent::__construct($info, $config);

        $this->userPassSourceName = $config['userPassSource']['name'] ?? 'campus-userpass';
        $this->spSourceName = $config['spSource']['name'] ?? 'default-sp';

        $userPassClassRef = $this->normalizeAuthnContextClassRef($config['userPassSource']['AuthnContextClassRef'] ?? []);
        $spClassRef = $this->normalizeAuthnContextClassRef($config['spSource']['AuthnContextClassRef'] ?? []);

        $this->sources = [
            [
                'source' => $this->userPassSourceName,
                'AuthnContextClassRef' => $userPassClassRef,
            ],
            [
                'source' => $this->spSourceName,
                'AuthnContextClassRef' => $spClassRef,
            ],
        ];
    }

    /**
     * Normalize AuthnContextClassRef to an array.
     *
     * @param mixed $ref The reference to normalize.
     * @return array The normalized array.
     */
    private function normalizeAuthnContextClassRef(mixed $ref): array
    {
        if (is_string($ref)) {
            return [$ref];
        }
        if (is_array($ref)) {
            return $ref;
        }
        return [];
    }

    /**
     * Start authentication process. Redirects to the source selection page.
     *
     * @param array &$state The state array.
     * @return void
     */
    public function authenticate(array &$state): void
    {
        // Check for various IdP hints in the request
        if (array_key_exists(self::AARC_IDP_HINT, $_REQUEST)) {
            $state[self::AARC_IDP_HINT] = $_REQUEST[self::AARC_IDP_HINT];
        }
        if (array_key_exists(self::AARC_DISCOVERY_HINT, $_REQUEST)) {
            $state[self::AARC_DISCOVERY_HINT] = $_REQUEST[self::AARC_DISCOVERY_HINT];
        }
        if (array_key_exists(self::AARC_DISCOVERY_HINT_URI, $_REQUEST)) {
            $state[self::AARC_DISCOVERY_HINT_URI] = $_REQUEST[self::AARC_DISCOVERY_HINT_URI];
        }
        if (array_key_exists(self::IDPHINT, $_REQUEST)) {
            $state[self::IDPHINT] = $_REQUEST[self::IDPHINT];
        }

        $state[self::AUTHID] = $this->authId;
        $state[self::SOURCESID] = $this->sources;
        $state[self::USER_PASS_SOURCE_NAME] = $this->userPassSourceName;
        $state[self::SP_SOURCE_NAME] = $this->spSourceName;

        // Save the state for the next step
        $id = State::saveState($state, self::STAGEID_USERPASS);

        $url = Module::getModuleURL('campusmultiauth/selectsource.php');
        $params = ['AuthState' => $id];

        (new HTTP())->redirectTrustedURL($url, $params);
    }

    /**
     * Delegate authentication to a specific source.
     *
     * @param string $authId The ID of the authentication source to use.
     * @param array $state The current state array.
     * @return void
     * @throws Exception If the authentication source is invalid.
     */
    public static function delegateAuthentication(string $authId, array $state): void
    {
        $as = Source::getById($authId);
        $validSources = array_map(fn($src) => $src['source'], $state[self::SOURCESID]);

        if ($as === null || !in_array($authId, $validSources, true)) {
            throw new Exception('Invalid authentication source: ' . $authId);
        }

        // Store the selected source for logout
        $session = Session::getSessionFromRequest();
        $session->setData(self::SESSION_SOURCE, $state[self::AUTHID], $authId, Session::DATA_TIMEOUT_SESSION_END);

        try {
            // Handle username/password login if the source is a UserPassBase subclass
            if (
                !empty($_POST['username']) && !empty($_POST['password']) &&
                is_subclass_of($as, UserPassBase::class)
            ) {
                $state[UserPassBase::AUTHID] = $authId;

                try {
                    UserPassBase::handleLogin(
                        State::saveState($state, UserPassBase::STAGEID),
                        $_POST['username'],
                        $_POST['password']
                    );
                } catch (Error\Error $e) {
                    if ($e->getMessage() === 'WRONGUSERPASS') {
                        $id = State::saveState($state, self::STAGEID_USERPASS);
                        $url = Module::getModuleURL('campusmultiauth/selectsource.php');
                        (new HTTP())->redirectTrustedURL($url, [
                            'AuthState' => $id,
                            'wrongUserPass' => true,
                        ]);
                    } else {
                        throw $e;
                    }
                }
            } else {
                // Delegate to the chosen authentication source
                $as->authenticate($state);
            }
        } catch (Error\Exception $e) {
            State::throwException($state, $e);
        } catch (Exception $e) {
            $e = new UnserializableException($e->getMessage(), $e->getCode(), $e);
            State::throwException($state, $e);
        }

        Source::completeAuth($state);
    }

    /**
     * Get a cookie value.
     *
     * @param string $name The name of the cookie (without prefix).
     * @return string|null The cookie value, or null if not set.
     */
    public static function getCookie(string $name): ?string
    {
        return $_COOKIE[self::COOKIE_PREFIX . $name] ?? null;
    }

    /**
     * Set a cookie.
     *
     * @param string $name The name of the cookie (without prefix).
     * @param string|null $value The value to set, or null to delete.
     * @return void
     */
    public static function setCookie(string $name, ?string $value): void
    {
        $prefixedName = self::COOKIE_PREFIX . $name;

        $params = [
            'lifetime' => self::COOKIE_LIFETIME,
            'path' => Configuration::getInstance()->getBasePath(),
            'httponly' => false,
            'secure' => true,
            'samesite' => 'Lax',
        ];

        (new HTTP())->setCookie($prefixedName, $value, $params, false);
    }

    /**
     * Extract the most square-like logo from IdP metadata.
     *
     * @param array $idpentry The IdP metadata entry.
     * @return string The URL of the most square logo, or an empty string.
     */
    public static function getMostSquareLikeImg(array $idpentry): string
    {
        if (empty($idpentry['UIInfo']['Logo'])) {
            return '';
        }

        $logos = $idpentry['UIInfo']['Logo'];
        if (count($logos) === 1) {
            return $logos[0]['url'];
        }

        $bestRatio = 1.0;
        $bestUrl = '';

        foreach ($logos as $logo) {
            $width = $logo['width'] ?? 1;
            $height = $logo['height'] ?? 1;
            if ($width <= 0 || $height <= 0) {
                continue;
            }
            $ratio = abs($height - $width) / ($height + $width);
            if ($ratio < $bestRatio) {
                $bestRatio = $ratio;
                $bestUrl = $logo['url'];
            }
        }

        return $bestUrl;
    }

    /**
     * Get IdPs based on a hint.
     *
     * @param array $hint The hint array.
     * @return array|null An array of entity IDs, or null.
     */
    public static function getHintedIdps(array $hint): ?array
    {
        $discoveryHint = null;

        if (array_key_exists(self::AARC_DISCOVERY_HINT_URI, $hint)) {
            $url = $hint[self::AARC_DISCOVERY_HINT_URI];
            // Validate URL to prevent SSRF
            if (!self::isAllowedHintUrl($url)) {
                Logger::warning('Blocked SSRF attempt for URL: ' . $url);
                return null;
            }
            $content = file_get_contents($url);
            if ($content === false) {
                Logger::warning('Could not fetch discovery hint URI: ' . $url);
                return null;
            }
            $discoveryHint = json_decode($content, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                Logger::warning('Invalid JSON from discovery hint URI.');
                return null;
            }
        } elseif (array_key_exists(self::AARC_DISCOVERY_HINT, $hint)) {
            $discoveryHint = $hint[self::AARC_DISCOVERY_HINT];
        } else {
            return null;
        }

        $metadataStorageHandler = MetaDataStorageHandler::getMetadataHandler();
        $metadata = $metadataStorageHandler->getList();

        $idps = [];

        if (array_key_exists(self::INCLUDE, $discoveryHint)) {
            if (empty($discoveryHint[self::INCLUDE])) {
                return [];
            }

            foreach ($discoveryHint[self::INCLUDE] as $key => $value) {
                if ($key === self::ALL_OF) {
                    $idps = array_merge($idps, self::getAllOfIdps($value, $metadata));
                } elseif ($key === self::ANY_OF) {
                    $idps = array_merge($idps, self::getAnyOfIdps($value, $metadata));
                }
            }
        } else {
            $idps = array_keys($metadata);
        }

        $idps = array_unique($idps);

        if (!empty($discoveryHint[self::EXCLUDE])) {
            foreach ($discoveryHint[self::EXCLUDE] as $key => $value) {
                if ($key === self::ALL_OF) {
                    $idps = array_diff($idps, self::getAllOfIdps($value, $metadata));
                } elseif ($key === self::ANY_OF) {
                    $r = self::getAnyOfIdps($value, $metadata);
                    $idps = array_diff($idps, $r);
                }
            }
        }

        return $idps;
    }

    /**
     * Check if a URL is allowed for fetching hints.
     *
     * @param string $url The URL to check.
     * @return bool True if allowed, false otherwise.
     */
    private static function isAllowedHintUrl(string $url): bool
    {
        $parsed = parse_url($url);
        if ($parsed === false || !isset($parsed['host'])) {
            return false;
        }

        // Get allowed domains from configuration
        $config = Configuration::getOptionalConfig('module_campusmultiauth.php');
        $allowedDomains = $config->getArray('allowed_hint_domains', []);

        // If no domains configured, reject all external URLs (only allow local files? but file:// may be disabled)
        if (empty($allowedDomains)) {
            // Allow only if scheme is not http/https (e.g., file, but better to reject for security)
            return false;
        }

        foreach ($allowedDomains as $domain) {
            if ($parsed['host'] === $domain) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get IdPs matching ALL criteria.
     *
     * @param array $claim The claim array.
     * @param array $metadata All metadata.
     * @param string|null $type Optional type hint.
     * @return array An array of entity IDs.
     */
    public static function getAllOfIdps(array $claim, array $metadata, ?string $type = null): array
    {
        $result = [];
        $isFirst = true;

        if ($type === null) {
            foreach ($claim as $array) {
                foreach ($array as $key => $value) {
                    switch ($key) {
                        case self::ALL_OF:
                            $matched = self::getAllOfIdps($value, $metadata);
                            break;
                        case self::ANY_OF:
                            $matched = self::getAnyOfIdps($value, $metadata);
                            break;
                        case self::ENTITY_CATEGORY:
                            $matched = self::getEntityCategoryIdps($value, $metadata);
                            break;
                        case self::ASSURANCE_CERTIFICATION:
                            $matched = self::getAssuranceCertificationIdps($value, $metadata);
                            break;
                        case self::REGISTRATION_AUTHORITY:
                            $matched = self::getRegistrationAuthorityIdps($value, $metadata);
                            break;
                        default:
                            $matched = [];
                    }
                    if ($isFirst) {
                        $result = $matched;
                        $isFirst = false;
                    } else {
                        $result = array_intersect($result, $matched);
                    }
                }
            }
        } else {
            foreach ($claim as $item) {
                switch ($type) {
                    case self::ENTITY_CATEGORY:
                        $matched = self::getEntityCategoryIdps([self::CONTAINS => $item], $metadata);
                        break;
                    case self::ASSURANCE_CERTIFICATION:
                        $matched = self::getAssuranceCertificationIdps([self::CONTAINS => $item], $metadata);
                        break;
                    default:
                        $matched = [];
                }
                if ($isFirst) {
                    $result = $matched;
                    $isFirst = false;
                } else {
                    $result = array_intersect($result, $matched);
                }
            }
        }

        return array_unique($result);
    }

    /**
     * Get IdPs matching ANY criteria.
     *
     * @param array $claim The claim array.
     * @param array $metadata All metadata.
     * @param string|null $type Optional type hint.
     * @return array An array of entity IDs.
     */
    public static function getAnyOfIdps(array $claim, array $metadata, ?string $type = null): array
    {
        $result = [];

        if ($type === null) {
            foreach ($claim as $array) {
                foreach ($array as $key => $value) {
                    $result = array_merge($result, match ($key) {
                        self::ALL_OF => self::getAllOfIdps($value, $metadata),
                        self::ANY_OF => self::getAnyOfIdps($value, $metadata),
                        self::ENTITY_CATEGORY => self::getEntityCategoryIdps($value, $metadata),
                        self::ASSURANCE_CERTIFICATION => self::getAssuranceCertificationIdps($value, $metadata),
                        self::REGISTRATION_AUTHORITY => self::getRegistrationAuthorityIdps($value, $metadata),
                        self::ENTITYID => self::getEntityidIdp($value, $metadata),
                        default => [],
                    });
                }
            }
        } else {
            foreach ($claim as $item) {
                $result = array_merge($result, match ($type) {
                    self::ENTITY_CATEGORY => self::getEntityCategoryIdps([self::CONTAINS => $item], $metadata),
                    self::ASSURANCE_CERTIFICATION => self::getAssuranceCertificationIdps([self::CONTAINS => $item], $metadata),
                    self::REGISTRATION_AUTHORITY => self::getRegistrationAuthorityIdps([self::EQUALS => $item], $metadata),
                    self::ENTITYID => self::getEntityidIdp([self::EQUALS => $item], $metadata),
                    default => [],
                });
            }
        }

        return array_unique($result);
    }

    /**
     * Get IdPs based on entity category.
     *
     * @param array $claim The claim.
     * @param array $metadata All metadata.
     * @return array An array of entity IDs.
     */
    public static function getEntityCategoryIdps(array $claim, array $metadata): array
    {
        $result = [];

        $firstKey = array_key_first($claim);
        switch ($firstKey) {
            case self::ALL_OF:
                $result = self::getAllOfIdps($claim[self::ALL_OF], $metadata, self::ENTITY_CATEGORY);
                break;
            case self::ANY_OF:
                $result = self::getAnyOfIdps($claim[self::ANY_OF], $metadata, self::ENTITY_CATEGORY);
                break;
            case self::CONTAINS:
                foreach ($metadata as $entityid => $idpMetadata) {
                    $categories = self::getIdpEntityCategories($idpMetadata);
                    if (self::contains($claim[self::CONTAINS], $categories)) {
                        $result[] = $entityid;
                    }
                }
                break;
        }

        return $result;
    }

    /**
     * Get IdPs based on assurance certification.
     *
     * @param array $claim The claim.
     * @param array $metadata All metadata.
     * @return array An array of entity IDs.
     */
    public static function getAssuranceCertificationIdps(array $claim, array $metadata): array
    {
        $result = [];

        $firstKey = array_key_first($claim);
        switch ($firstKey) {
            case self::ALL_OF:
                $result = self::getAllOfIdps($claim[self::ALL_OF], $metadata, self::ASSURANCE_CERTIFICATION);
                break;
            case self::ANY_OF:
                $result = self::getAnyOfIdps($claim[self::ANY_OF], $metadata, self::ASSURANCE_CERTIFICATION);
                break;
            case self::CONTAINS:
                foreach ($metadata as $entityid => $idpMetadata) {
                    $certifications = self::getIdpAssuranceCertifications($idpMetadata);
                    if (self::contains($claim[self::CONTAINS], $certifications)) {
                        $result[] = $entityid;
                    }
                }
                break;
        }

        return $result;
    }

    /**
     * Get IdPs based on registration authority.
     *
     * @param array $claim The claim.
     * @param array $metadata All metadata.
     * @return array An array of entity IDs.
     */
    public static function getRegistrationAuthorityIdps(array $claim, array $metadata): array
    {
        $result = [];

        $firstKey = array_key_first($claim);
        switch ($firstKey) {
            case self::ANY_OF:
                $result = self::getAnyOfIdps($claim[self::ANY_OF], $metadata, self::REGISTRATION_AUTHORITY);
                break;
            case self::EQUALS:
                $value = $claim[self::EQUALS];
                foreach ($metadata as $entityid => $idpMetadata) {
                    $ra = $idpMetadata['RegistrationInfo']['registrationAuthority'] ?? null;
                    if ($ra !== null && self::equals($ra, $value)) {
                        $result[] = $entityid;
                    }
                }
                break;
            case self::MATCHES:
                $pattern = $claim[self::MATCHES];
                foreach ($metadata as $entityid => $idpMetadata) {
                    $ra = $idpMetadata['RegistrationInfo']['registrationAuthority'] ?? null;
                    if ($ra !== null && self::matches($ra, $pattern)) {
                        $result[] = $entityid;
                    }
                }
                break;
        }

        return $result;
    }

    /**
     * Get IdPs based on entity ID.
     *
     * @param array $claim The claim.
     * @param array $metadata All metadata.
     * @return array An array of entity IDs.
     */
    public static function getEntityidIdp(array $claim, array $metadata): array
    {
        $result = [];

        $firstKey = array_key_first($claim);
        switch ($firstKey) {
            case self::ANY_OF:
                $result = self::getAnyOfIdps($claim[self::ANY_OF], $metadata, self::ENTITYID);
                break;
            case self::EQUALS:
                $entityid = $claim[self::EQUALS];
                if (isset($metadata[$entityid])) {
                    $result[] = $entityid;
                }
                break;
            case self::MATCHES:
                $pattern = $claim[self::MATCHES];
                foreach (array_keys($metadata) as $entityid) {
                    if (self::matches($entityid, $pattern)) {
                        $result[] = $entityid;
                    }
                }
                break;
        }

        return $result;
    }

    /**
     * Get entity categories for an IdP.
     *
     * @param array $idpMetadata IdP metadata.
     * @return array Entity categories.
     */
    public static function getIdpEntityCategories(array $idpMetadata): array
    {
        return self::getAttrValues($idpMetadata, self::ENTITY_CATEGORY_ATTR_NAME);
    }

    /**
     * Get assurance certifications for an IdP.
     *
     * @param array $idpMetadata IdP metadata.
     * @return array Assurance certifications.
     */
    public static function getIdpAssuranceCertifications(array $idpMetadata): array
    {
        return self::getAttrValues($idpMetadata, self::ASSURANCE_CERTIFICATION_ATTR_NAME);
    }

    /**
     * Extract attribute values from metadata entityDescriptor XML.
     *
     * @param array $idpMetadata IdP metadata.
     * @param string $attrName The attribute name to extract.
     * @return array The extracted values.
     *
     * @deprecated This method relies on XML parsing and may be inefficient.
     *             Consider a more robust metadata handling solution.
     */
    public static function getAttrValues(array $idpMetadata, string $attrName): array
    {
        $result = [];

        if (empty($idpMetadata['entityDescriptor'])) {
            return $result;
        }

        $xmlStr = base64_decode($idpMetadata['entityDescriptor'], true);
        if ($xmlStr === false) {
            Logger::warning('Could not base64 decode entityDescriptor.');
            return $result;
        }

        // Disable external entity loading to prevent XXE attacks
        $old = libxml_disable_entity_loader(true);
        $xml = simplexml_load_string($xmlStr);
        libxml_disable_entity_loader($old);

        if ($xml === false) {
            Logger::warning('Could not parse entityDescriptor XML.');
            return $result;
        }

        $xml->registerXPathNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $xml->registerXPathNamespace('mdattr', 'urn:oasis:names:tc:SAML:metadata:attribute');
        $xml->registerXPathNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');

        $xpathQuery = sprintf('//saml:Attribute[@Name="%s"]/saml:AttributeValue', $attrName);
        $attrs = $xml->xpath($xpathQuery);
        if ($attrs === false) {
            return $result;
        }

        foreach ($attrs as $attr) {
            $result[] = $attr->__toString();
        }

        return $result;
    }

    /**
     * Check if a value is in an array.
     *
     * @param mixed $needle The value to find.
     * @param array $haystack The array to search.
     * @return bool True if found, false otherwise.
     */
    public static function contains(mixed $needle, array $haystack): bool
    {
        return in_array($needle, $haystack, true);
    }

    /**
     * Check if two strings are equal.
     *
     * @param string $string1 First string.
     * @param string $string2 Second string.
     * @return bool True if equal, false otherwise.
     */
    public static function equals(string $string1, string $string2): bool
    {
        return $string1 === $string2;
    }

    /**
     * Check if a string matches a regular expression pattern.
     *
     * @param string $string The string to test.
     * @param string $pattern The regex pattern.
     * @return bool True if matches, false otherwise.
     */
    public static function matches(string $string, string $pattern): bool
    {
        return preg_match($pattern, $string) === 1;
    }

    /**
     * Check if an IdP is in the cookie list.
     *
     * @param array $idps The list of IdPs from the cookie.
     * @param string $entityid The entity ID to check.
     * @return bool True if found, false otherwise.
     */
    public static function isIdpInCookie(array $idps, string $entityid): bool
    {
        foreach ($idps as $idp) {
            if (($idp[self::ENTITYID] ?? null) === $entityid) {
                return true;
            }
        }
        return false;
    }

    /**
     * Find which searchbox components should be displayed based on hints.
     *
     * @param mixed $hint The hint.
     * @param array $config The module configuration.
     * @param array|null $state The state array.
     * @return array Indices of searchbox components to display.
     */
    public static function findSearchboxesToDisplay($hint, array $config, $state): array
    {
        $result = [];

        for ($i = 0; $i < count($config['components']); $i++) {
            if ($config['components'][$i]['name'] === 'searchbox') {
                $ch = curl_init();

                if ($hint !== null) {
                    curl_setopt(
                        $ch,
                        CURLOPT_URL,
                        Module::getModuleURL(
                            'campusmultiauth/idpSearch.php?' . self::IDPHINT . '=' . json_encode(
                                $hint
                            ) . '&skipMatching=true' . '&index=' . $i
                        )
                    );
                } elseif (array_key_exists(self::AARC_DISCOVERY_HINT_URI, (array)$state)) {
                    curl_setopt(
                        $ch,
                        CURLOPT_URL,
                        Module::getModuleURL(
                            'campusmultiauth/idpSearch.php?' . self::AARC_DISCOVERY_HINT_URI . '=' . json_encode(
                                $state['aarc_discovery_hint_uri']
                            ) . '&skipMatching=true' . '&index=' . $i
                        )
                    );
                } else {
                    curl_setopt(
                        $ch,
                        CURLOPT_URL,
                        Module::getModuleURL(
                            'campusmultiauth/idpSearch.php?' . self::AARC_DISCOVERY_HINT . '=' . json_encode(
                                $state['aarc_discovery_hint']
                            ) . '&skipMatching=true' . '&index=' . $i
                        )
                    );
                }

                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

                $idps = json_decode(curl_exec($ch));

                curl_close($ch);

                if (!empty($idps->items)) {
                    $result[] = $i;
                }
            }
        }

        return $result;
    }

    /**
     * Find which individual identities components should be displayed based on hinted IdPs.
     *
     * @param array $hintedIdps The hinted IdPs.
     * @param array $config The module configuration.
     * @return array Indices of individual identities components to display.
     */
    public static function findIndividualIdentitiesToDisplay(array $hintedIdps, array $config): array
    {
        $result = [];

        for ($i = 0; $i < count($config['components']); $i++) {
            if ($config['components'][$i]['name'] === 'individual_identities') {
                $componentToDisplay = false;

                foreach ($config['components'][$i]['identities'] as $identity) {
                    if (in_array($identity['upstream_idp'], $hintedIdps, true)) {
                        $componentToDisplay = true;
                        break;
                    }
                }

                if ($componentToDisplay) {
                    $result[] = $i;
                }
            }
        }

        return $result;
    }

    /**
     * Get positions of "or" separators.
     *
     * @param array $searchboxesToDisplay Searchbox indices to display.
     * @param array $individualIdentitiesToDisplay Individual identities indices to display.
     * @param array $idphint IdP hint.
     * @param array $config Module configuration.
     * @return array Positions.
     */
    public static function getOrPositions(
        array $searchboxesToDisplay,
        array $individualIdentitiesToDisplay,
        array $idphint,
        array $config
    ): array {
        $result = [];

        $componentsToDisplay = [];
        $endColComponent = -1;

        for ($i = 0; $i < count($config['components']); $i++) {
            if (
                $config['components'][$i]['name'] === 'local_login' && in_array(
                    $config['components'][$i]['entityid'],
                    $idphint,
                    true
                )
            ) {
                $componentsToDisplay[] = $i;
            }

            if (!empty($config['components'][$i]['end_col']) && $config['components'][$i]['end_col'] === true) {
                $endColComponent = $i;
            }
        }

        $componentsToDisplay = array_merge($componentsToDisplay, $searchboxesToDisplay, $individualIdentitiesToDisplay);

        foreach ($componentsToDisplay as $index1) {
            if ($index1 <= $endColComponent) {
                foreach ($componentsToDisplay as $index2) {
                    if ($index1 < $index2 && $index2 <= $endColComponent) {
                        $result[] = $index1;
                        break;
                    }
                }
            } else {
                foreach ($componentsToDisplay as $index2) {
                    if ($index1 < $index2) {
                        $result[] = $index1;
                        break;
                    }
                }
            }
        }

        return $result;
    }

    /**
     * Filter metadata by search term.
     *
     * @param array $metadata All metadata.
     * @param string $searchTerm The search term.
     * @return array Filtered metadata.
     */
    public static function getIdpsMatchedBySearchTerm(array $metadata, string $searchTerm): array
    {
        $filteredMetadata = [];

        $transliterator = Transliterator::createFromRules(
            ':: Any-Latin; :: Latin-ASCII; :: NFD; :: [:Nonspacing Mark:] Remove; :: Lower(); :: NFC;',
            Transliterator::FORWARD
        );

        foreach ($metadata as $entityid => $idpentry) {
            if (!empty($idpentry['name']) && is_array($idpentry['name'])) {
                foreach ($idpentry['name'] as $key => $value) {
                    if (
                        str_contains(
                            $transliterator->transliterate($value),
                            $transliterator->transliterate($searchTerm)
                        )
                    ) {
                        $filteredMetadata[$entityid] = $idpentry;
                        break;
                    }
                }
            }

            if (
                !in_array($idpentry, $filteredMetadata, true) && !empty($idpentry['description']) && is_array(
                    $idpentry['description']
                )
            ) {
                foreach ($idpentry['description'] as $key => $value) {
                    if (
                        str_contains(
                            $transliterator->transliterate($value),
                            $transliterator->transliterate($searchTerm)
                        )
                    ) {
                        $filteredMetadata[$entityid] = $idpentry;
                        break;
                    }
                }
            }

            if (
                !in_array($idpentry, $filteredMetadata, true) && !empty($idpentry['url']) && is_array(
                    $idpentry['url']
                )
            ) {
                foreach ($idpentry['url'] as $key => $value) {
                    if (str_contains(strtolower($value), strtolower($searchTerm))) {
                        $filteredMetadata[$entityid] = $idpentry;
                        break;
                    }
                }
            }
        }

        return $filteredMetadata;
    }

    /**
     * @deprecated
     */
    public static function useLoginURL($state, $config, $restartUrl)
    {
        $queryVarsStr = parse_url($state['saml:RelayState'], PHP_URL_QUERY);
        if ($queryVarsStr) {
            parse_str($queryVarsStr, $queryVars);

            if (!empty($queryVars['client_id'])) {
                $OIDCClientID = $queryVars['client_id'];
                $OIDCLoginURL = self::getLoginURL($config, $OIDCClientID);
                if ($OIDCLoginURL) {
                    $restartUrl = $OIDCLoginURL;
                }
            }
        }

        return $restartUrl;
    }

    /**
     * @deprecated
     */
    public static function getLoginURL($config, $clientId)
    {
        $hostname = $config->getString('ldap.hostname');
        $port = $config->getInteger('ldap.port', 389);
        $enable_tls = $config->getBoolean('ldap.enable_tls', false);
        $debug = $config->getBoolean('ldap.debug', false);
        $referrals = $config->getBoolean('ldap.referrals', true);
        $timeout = $config->getInteger('ldap.timeout', 0);
        $username = $config->getString('ldap.username', null);
        $password = $config->getString('ldap.password', null);

        try {
            $ldap = new Ldap($hostname, $enable_tls, $debug, $timeout, $port, $referrals);
        } catch (\Exception $e) {
            Logger::warning($e->getMessage());

            return null;
        }
        $ldap->bind($username, $password);

        $identifierAttrName = $config->getString('identifier.attr.name', 'OIDCClientID');
        $urlAttrName = $config->getString('url.attr.name', 'rploginurl');

        $base = $config->getString('ldap.basedn');
        $filter = '(&(objectClass=perunFacility)(' . $identifierAttrName . '=' . $clientId . '))';

        try {
            $entries = $ldap->searchformultiple([$base], $filter, [$urlAttrName], [], true, false);
        } catch (\Exception $e) {
            $entries = [];
        }

        if (count($entries) < 1 || empty($entries[0][$urlAttrName])) {
            return null;
        }

        return $entries[0][$urlAttrName][0];
    }

    /**
     * Logout from the selected source.
     *
     * @param array &$state The state array.
     * @return void
     * @throws Exception If the source is invalid.
     */
    public function logout(array &$state): void
    {
        Assert::isArray($state, 'State must be an array.');

        $session = Session::getSessionFromRequest();
        $authId = $session->getData(self::SESSION_SOURCE, $this->authId);

        $source = Source::getById($authId);
        if ($source === null) {
            throw new Exception('Invalid authentication source during logout: ' . $authId);
        }

        $source->logout($state);
    }
}
