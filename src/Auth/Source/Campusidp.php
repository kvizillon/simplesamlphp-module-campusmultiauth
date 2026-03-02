<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth\Auth\Source;

use Exception;
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
use SimpleSAML\Utils;
use Transliterator;

class Campusidp extends Source
{
    public const AUTHID = '\SimpleSAML\Module\campusidp\Auth\Source\Campusidp.AuthId';

    public const STAGEID_USERPASS = '\SimpleSAML\Module\core\Auth\UserPassBase.state';

    public const SOURCESID = '\SimpleSAML\Module\campusidp\Auth\Source\Campusidp.SourceId';

    public const SESSION_SOURCE = 'campusmultiauth:selectedSource';

    public const USER_PASS_SOURCE_NAME = 'userPassSourceName';

    public const SP_SOURCE_NAME = 'spSourceName';

    public const COOKIE_PREVIOUS_IDPS = 'previous_idps';

    public const COOKIE_PREFIX = 'campusidp_';

    public const IDP_HINT_BUTTONS_LIMIT = 5;

    // idp hinting

    public const IDPHINT = 'idphint';

    public const AARC_IDP_HINT = 'aarc_idp_hint';

    public const AARC_DISCOVERY_HINT = 'aarc_discovery_hint';

    public const AARC_DISCOVERY_HINT_URI = 'aarc_discovery_hint_uri';

    public const INCLUDE = 'include';

    public const EXCLUDE = 'exclude';

    public const ALL_OF = 'all_of';

    public const ANY_OF = 'any_of';

    public const ENTITY_CATEGORY = 'entity_category';

    public const ASSURANCE_CERTIFICATION = 'assurance_certification';

    public const REGISTRATION_AUTHORITY = 'registration_authority';

    public const ENTITYID = 'entityid';

    public const CONTAINS = 'contains';

    public const EQUALS = 'equals';

    public const MATCHES = 'matches';

    public const ENTITY_CATEGORY_ATTR_NAME = 'http://macedir.org/entity-category';

    public const ASSURANCE_CERTIFICATION_ATTR_NAME = 'urn:oasis:names:tc:SAML:attribute:assurance-certification';

    private $sources;

    private $userPassSourceName;

    private $spSourceName;

    public function __construct($info, $config)
    {
        parent::__construct($info, $config);

        $this->sources = [];

        $this->userPassSourceName = !empty($config['userPassSource']['name'])
            ? $config['userPassSource']['name'] : 'campus-userpass';

        $userPassClassRef = [];
        if (!empty($config['userPassSource']['AuthnContextClassRef'])) {
            $ref = $config['userPassSource']['AuthnContextClassRef'];
            if (is_string($ref)) {
                $userPassClassRef = [$ref];
            } else {
                $userPassClassRef = $ref;
            }
        }

        $this->sources[] = [
            'source' => $this->userPassSourceName,
            'AuthnContextClassRef' => $userPassClassRef,
        ];

        $this->spSourceName = !empty($config['spSource']['name']) ? $config['spSource']['name'] : 'default-sp';

        $spClassRef = [];
        if (!empty($config['spSource']['AuthnContextClassRef'])) {
            $ref = $config['spSource']['AuthnContextClassRef'];
            if (is_string($ref)) {
                $spClassRef = [$ref];
            } else {
                $spClassRef = $ref;
            }
        }

        $this->sources[] = [
            'source' => $this->spSourceName,
            'AuthnContextClassRef' => $spClassRef,
        ];
    }

    public function authenticate(&$state)
    {
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

        // Save the $state array, so that we can restore if after a redirect
        $id = State::saveState($state, self::STAGEID_USERPASS);

        /* Redirect to the select source page. We include the identifier of the
         * saved state array as a parameter to the login form
         */
        $url = Module::getModuleURL('campusmultiauth/selectsource.php');
        $params = [
            'AuthState' => $id,
        ];

        Utils\HTTP::redirectTrustedURL($url, $params);

        // The previous function never returns, so this code is never executed
        assert(false);
    }

    public static function delegateAuthentication($authId, $state)
    {
        $as = Auth\Source::getById($authId);
        $valid_sources = array_map(function ($src) {
            return $src['source'];
        }, $state[self::SOURCESID]);
        if ($as === null || !in_array($authId, $valid_sources, true)) {
            throw new Exception('Invalid authentication source: ' . $authId);
        }

        // Save the selected authentication source for the logout process.
        $session = Session::getSessionFromRequest();
        $session->setData(self::SESSION_SOURCE, $state[self::AUTHID], $authId, Session::DATA_TIMEOUT_SESSION_END);

        try {
            if (
                !empty($_POST['username']) && !empty($_POST['password']) && is_subclass_of(
                    $as,
                    '\SimpleSAML\Module\core\Auth\UserPassBase'
                )
            ) {
                $state[UserPassBase::AUTHID] = $authId;

                try {
                    UserPassBase::handleLogin(
                        State::saveState($state, UserPassBase::STAGEID),
                        $_POST['username'],
                        $_POST['password']
                    );
                } catch (\SimpleSAML\Error\Error $e) {
                    if ($e->getMessage() === 'WRONGUSERPASS') {
                        $id = State::saveState($state, self::STAGEID_USERPASS);
                        $url = Module::getModuleURL('campusmultiauth/selectsource.php');
                        $params = [
                            'AuthState' => $id,
                            'wrongUserPass' => true,
                        ];

                        Utils\HTTP::redirectTrustedURL($url, $params);
                    } else {
                        throw $e;
                    }
                }
            } else {
                $as->authenticate($state);
            }
        } catch (Error\Exception $e) {
            Auth\State::throwException($state, $e);
        } catch (Exception $e) {
            $e = new UnserializableException($e);
            Auth\State::throwException($state, $e);
        }
        Auth\Source::completeAuth($state);
    }

    public static function getCookie($name)
    {
        $prefixedName = self::COOKIE_PREFIX . $name;
        if (array_key_exists($prefixedName, $_COOKIE)) {
            return $_COOKIE[$prefixedName];
        }
        return null;
    }

    public static function setCookie($name, $value)
    {
        $prefixedName = self::COOKIE_PREFIX . $name;

        $params = [
            // we save the cookies for 90 days
            'lifetime' => (60 * 60 * 24 * 90),
            // the base path for cookies. This should be the installation directory for SimpleSAMLphp
            'path' => Configuration::getInstance()->getBasePath(),
            'httponly' => false,
        ];

        Utils\HTTP::setCookie($prefixedName, $value, $params, false);
    }

    public static function getMostSquareLikeImg($idpentry)
    {
        if (!empty($idpentry['UIInfo']['Logo'])) {
            if (count($idpentry['UIInfo']['Logo']) === 1) {
                $item['image'] = $idpentry['UIInfo']['Logo'][0]['url'];
            } else {
                $logoSizeRatio = 1; // impossible value
                $candidateLogoUrl = null;

                foreach ($idpentry['UIInfo']['Logo'] as $logo) {
                    $ratio = abs($logo['height'] - $logo['width']) / ($logo['height'] + $logo['width']);

                    if ($ratio < $logoSizeRatio) { // then we found more square-like logo
                        $logoSizeRatio = $ratio;
                        $candidateLogoUrl = $logo['url'];
                    }
                }

                $item['image'] = $candidateLogoUrl;
            }

            return $item['image'];
        }
        return '';
    }

    public static function getHintedIdps($hint)
    {
        if (array_key_exists(self::AARC_DISCOVERY_HINT_URI, $hint)) {
            $discoveryHint = json_decode(file_get_contents($hint[self::AARC_DISCOVERY_HINT_URI]), true);
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
            } else {
                foreach ($discoveryHint[self::INCLUDE] as $key => $value) {
                    if ($key === self::ALL_OF) {
                        $idps = array_merge($idps, self::getAllOfIdps($value, $metadata));
                    } elseif ($key === self::ANY_OF) {
                        $idps = array_merge($idps, self::getAnyOfIdps($value, $metadata));
                    }
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

    public static function getAllOfIdps($claim, $metadata, $type = null)
    {
        $result = [];
        $isFirst = true;

        if ($type === null) {
            foreach ($claim as $array) {
                foreach ($array as $key => $value) {
                    switch ($key) {
                        case self::ALL_OF:
                            $isFirst ?
                                $result = array_merge($result, self::getAllOfIdps($value, $metadata)) :
                                $result = array_intersect($result, self::getAllOfIdps($value, $metadata));
                            $isFirst = false;
                            break;
                        case self::ANY_OF:
                            $isFirst ?
                                $result = array_merge($result, self::getAnyOfIdps($value, $metadata)) :
                                $result = array_intersect($result, self::getAnyOfIdps($value, $metadata));
                            $isFirst = false;
                            break;
                        case self::ENTITY_CATEGORY:
                            $isFirst ?
                                $result = array_merge($result, self::getEntityCategoryIdps($value, $metadata)) :
                                $result = array_intersect($result, self::getEntityCategoryIdps($value, $metadata));
                            $isFirst = false;
                            break;
                        case self::ASSURANCE_CERTIFICATION:
                            $isFirst ?
                                $result = array_merge($result, self::getAssuranceCertificationIdps($value, $metadata)) :
                                $result = array_intersect(
                                    $result,
                                    self::getAssuranceCertificationIdps($value, $metadata)
                                );
                            $isFirst = false;

                            break;
                        case self::REGISTRATION_AUTHORITY:
                            $isFirst ?
                                $result = array_merge($result, self::getRegistrationAuthorityIdps($value, $metadata)) :
                                $result = array_intersect(
                                    $result,
                                    self::getRegistrationAuthorityIdps($value, $metadata)
                                );
                            $isFirst = false;
                            break;
                        default:
                            break;
                    }
                }
            }
        } else {
            foreach ($claim as $item) {
                switch ($type) {
                    case self::ENTITY_CATEGORY:
                        $isFirst ?
                            $result = array_merge(
                                $result,
                                self::getEntityCategoryIdps([self::CONTAINS => $item], $metadata)
                            ) :
                            $result = array_intersect(
                                $result,
                                self::getEntityCategoryIdps([self::CONTAINS => $item], $metadata)
                            );
                        $isFirst = false;
                        break;
                    case self::ASSURANCE_CERTIFICATION:
                        $isFirst ?
                            $result = array_merge(
                                $result,
                                self::getAssuranceCertificationIdps([self::CONTAINS => $item], $metadata)
                            ) :
                            $result = array_intersect(
                                $result,
                                self::getAssuranceCertificationIdps([self::CONTAINS => $item], $metadata)
                            );
                        $isFirst = false;
                        break;
                    default:
                        break;
                }
            }
        }

        return array_unique($result);
    }

    public static function getAnyOfIdps($claim, $metadata, $type = null)
    {
        $result = [];

        if ($type === null) {
            foreach ($claim as $array) {
                foreach ($array as $key => $value) {
                    switch ($key) {
                        case self::ALL_OF:
                            $result = array_merge($result, self::getAllOfIdps($value, $metadata));
                            break;
                        case self::ANY_OF:
                            $result = array_merge($result, self::getAnyOfIdps($value, $metadata));
                            break;
                        case self::ENTITY_CATEGORY:
                            $result = array_merge($result, self::getEntityCategoryIdps($value, $metadata));
                            break;
                        case self::ASSURANCE_CERTIFICATION:
                            $result = array_merge($result, self::getAssuranceCertificationIdps($value, $metadata));
                            break;
                        case self::REGISTRATION_AUTHORITY:
                            $result = array_merge($result, self::getRegistrationAuthorityIdps($value, $metadata));
                            break;
                        case self::ENTITYID:
                            $result = array_merge($result, self::getEntityidIdp($value, $metadata));
                            break;
                        default:
                            break;
                    }
                }
            }
        } else {
            foreach ($claim as $item) {
                switch ($type) {
                    case self::ENTITY_CATEGORY:
                        $result = array_merge(
                            $result,
                            self::getEntityCategoryIdps([self::CONTAINS => $item], $metadata)
                        );
                        break;
                    case self::ASSURANCE_CERTIFICATION:
                        $result = array_merge(
                            $result,
                            self::getAssuranceCertificationIdps([self::CONTAINS => $item], $metadata)
                        );
                        break;
                    case self::REGISTRATION_AUTHORITY:
                        $result = array_merge(
                            $result,
                            self::getRegistrationAuthorityIdps([self::EQUALS => $item], $metadata)
                        );
                        break;
                    case self::ENTITYID:
                        $result = array_merge(
                            $result,
                            self::getEntityidIdp([self::EQUALS => $item], $metadata)
                        );
                        break;
                    default:
                        break;
                }
            }
        }

        return array_unique($result);
    }

    public static function getEntityCategoryIdps($claim, $metadata)
    {
        $result = [];

        switch (array_key_first($claim)) {
            case self::ALL_OF:
                $result = array_merge(
                    $result,
                    self::getAllOfIdps($claim[self::ALL_OF], $metadata, self::ENTITY_CATEGORY)
                );
                break;
            case self::ANY_OF:
                $result = array_merge(
                    $result,
                    self::getAnyOfIdps($claim[self::ANY_OF], $metadata, self::ENTITY_CATEGORY)
                );
                break;
            case self::CONTAINS:
                foreach ($metadata as $entityid => $idpMetadata) {
                    $entityCategories = self::getIdpEntityCategories($idpMetadata);

                    if (self::contains($claim[self::CONTAINS], $entityCategories)) {
                        $result[] = $entityid;
                    }
                }
                break;
            default:
                break;
        }

        return $result;
    }

    public static function getAssuranceCertificationIdps($claim, $metadata)
    {
        $result = [];

        switch (array_key_first($claim)) {
            case self::ALL_OF:
                $result = array_merge(
                    $result,
                    self::getAllOfIdps($claim[self::ALL_OF], $metadata, self::ASSURANCE_CERTIFICATION)
                );
                break;
            case self::ANY_OF:
                $result = array_merge(
                    $result,
                    self::getAnyOfIdps($claim[self::ANY_OF], $metadata, self::ASSURANCE_CERTIFICATION)
                );
                break;
            case self::CONTAINS:
                foreach ($metadata as $entityid => $idpMetadata) {
                    $assuranceCertifications = self::getIdpAssuranceCertifications($idpMetadata);

                    if (self::contains($claim[self::CONTAINS], $assuranceCertifications)) {
                        $result[] = $entityid;
                    }
                }
                break;
            default:
                break;
        }

        return $result;
    }

    public static function getRegistrationAuthorityIdps($claim, $metadata)
    {
        $result = [];

        switch (array_key_first($claim)) {
            case self::ANY_OF:
                $result = array_merge(
                    $result,
                    self::getAnyOfIdps($claim[self::ANY_OF], $metadata, self::REGISTRATION_AUTHORITY)
                );
                break;
            case self::EQUALS:
                foreach ($metadata as $entityid => $idpMetadata) {
                    if (
                        !empty($idpMetadata['RegistrationInfo']['registrationAuthority']) &&
                        self::equals($idpMetadata['RegistrationInfo']['registrationAuthority'], $claim[self::EQUALS])
                    ) {
                        $result[] = $entityid;
                    }
                }
                break;
            case self::MATCHES:
                foreach ($metadata as $entityid => $idpMetadata) {
                    if (
                        !empty($idpMetadata['RegistrationInfo']['registrationAuthority']) &&
                        self::matches($idpMetadata['RegistrationInfo']['registrationAuthority'], $claim[self::MATCHES])
                    ) {
                        $result[] = $entityid;
                    }
                }
                break;
            default:
                break;
        }

        return $result;
    }

    public static function getEntityidIdp($claim, $metadata)
    {
        $result = [];

        switch (array_key_first($claim)) {
            case self::ANY_OF:
                $result = array_merge($result, self::getAnyOfIdps($claim[self::ANY_OF], $metadata, self::ENTITYID));
                break;
            case self::EQUALS:
                if (self::contains($claim[self::EQUALS], array_keys($metadata))) {
                    $result[] = $claim[self::EQUALS];
                }
                break;
            case self::MATCHES:
                foreach (array_keys($metadata) as $entityid) {
                    if (self::matches($entityid, $claim[self::MATCHES])) {
                        $result[] = $entityid;
                    }
                }
                break;
            default:
                break;
        }

        return $result;
    }

    public static function getIdpEntityCategories($idpMetadata)
    {
        return self::getAttrValues($idpMetadata, self::ENTITY_CATEGORY_ATTR_NAME);
    }

    public static function getIdpAssuranceCertifications($idpMetadata)
    {
        return self::getAttrValues($idpMetadata, self::ASSURANCE_CERTIFICATION_ATTR_NAME);
    }

    /**
     * @deprecated
     */
    public static function getAttrValues($idpMetadata, $attrName)
    {
        $result = [];

        if (empty($idpMetadata['entityDescriptor'])) {
            return $result;
        }

        $xmlStr = base64_decode($idpMetadata['entityDescriptor']);
        $xml = @simplexml_load_string($xmlStr); // temporary solution

        $xml->registerXPathNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $xml->registerXPathNamespace('mdattr', 'urn:oasis:names:tc:SAML:metadata:attribute');
        $xml->registerXPathNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');

        $attrs = $xml->xpath('//saml:Attribute[@Name="' . $attrName . '"]/saml:AttributeValue');
        foreach ($attrs as $attr) {
            $result[] = $attr->__toString();
        }

        return $result;
    }

    public static function contains($needle, $haystack)
    {
        return in_array($needle, $haystack);
    }

    public static function equals($string1, $string2)
    {
        return $string1 === $string2;
    }

    public static function matches($string, $pattern)
    {
        return preg_match($pattern, $string) === 1;
    }

    public static function isIdpInCookie($idps, $entityid)
    {
        foreach ($idps as $idp) {
            if ($idp[self::ENTITYID] === $entityid) {
                return true;
            }
        }

        return false;
    }

    public static function findSearchboxesToDisplay($hint, $config, $state)
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
                } elseif (array_key_exists(self::AARC_DISCOVERY_HINT_URI, $state)) {
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

    public static function findIndividualIdentitiesToDisplay($hintedIdps, $config)
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

    public static function getOrPositions($searchboxesToDisplay, $individualIdentitiesToDisplay, $idphint, $config)
    {
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

    public static function getIdpsMatchedBySearchTerm($metadata, $searchTerm)
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

    public function logout(&$state)
    {
        assert(is_array($state));

        // Get the source that was used to authenticate
        $session = Session::getSessionFromRequest();
        $authId = $session->getData(self::SESSION_SOURCE, $this->authId);

        $source = Auth\Source::getById($authId);
        if ($source === null) {
            throw new Exception('Invalid authentication source during logout: ' . $authId);
        }
        // Then, do the logout on it
        $source->logout($state);
    }
}
