<?php

declare(strict_types=1);

use League\CommonMark\CommonMarkConverter;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module;
use SimpleSAML\Module\campusmultiauth\Auth\Process\RememberMe;
use SimpleSAML\Module\campusmultiauth\Auth\Source\Campusidp;
use SimpleSAML\Module\campusmultiauth\Utils;
use SimpleSAML\XHTML\Template;

if (!array_key_exists('AuthState', $_REQUEST) && !array_key_exists('authstate', $_POST)) {
    throw new BadRequest('Missing AuthState parameter.');
}

empty($_REQUEST['AuthState']) ? $authStateId = $_POST['authstate'] : $authStateId = $_REQUEST['AuthState'];
$state = State::loadState($authStateId, Campusidp::STAGEID_USERPASS);

$metadataStorageHandler = MetaDataStorageHandler::getMetadataHandler();
$metadata = $metadataStorageHandler->getList();

$wayfConfig = Configuration::getConfig('module_campusmultiauth.php')->toArray();

if (array_key_exists('aarc_idp_hint', $state)) {
    $parts = explode('?', urldecode($state['aarc_idp_hint']), 2);

    if (!empty($metadata[$parts[0]])) {
        $state['saml:idp'] = $parts[0];
        Campusidp::delegateAuthentication($state[Campusidp::SP_SOURCE_NAME], $state);
    }
}

$hintedIdps = Campusidp::getHintedIdps($state);

if ($hintedIdps !== null || array_key_exists('idphint', $state)) {
    if ($hintedIdps !== null && count($hintedIdps) === 1) {
        $state['saml:idp'] = array_pop($hintedIdps);
        Campusidp::delegateAuthentication($state[Campusidp::SP_SOURCE_NAME], $state);
    } elseif (
        $hintedIdps === null && array_key_exists('idphint', $state)
        && count(explode(',', $state['idphint'])) === 1
    ) {
        $state['saml:idp'] = urldecode($parts[0]);
        Campusidp::delegateAuthentication($state[Campusidp::SP_SOURCE_NAME], $state);
    } else {
        $sendParsedHint = true;

        if ($hintedIdps === null) {
            $parts = explode(',', $state['idphint']);

            $hintedIdps = [];
            foreach ($parts as $part) {
                $hintedIdps[] = urldecode($part);
            }
        } else {
            $sendParsedHint = false;
        }

        if (count($hintedIdps) <= Campusidp::IDP_HINT_BUTTONS_LIMIT) {
            $ch = curl_init();

            curl_setopt(
                $ch,
                CURLOPT_URL,
                Module::getModuleURL('campusmultiauth/idpSearch.php?idphint=' . json_encode($hintedIdps))
            );
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

            $idpsAsConfigItems = json_decode(curl_exec($ch));
            curl_close($ch);

            $hintComponentConfig = [];
            $hintComponentConfig['name'] = 'individual_identities';
            $hintComponentConfig['priority'] = 'primary';
            $hintComponentConfig['title'] = '';
            $hintComponentConfig['number_shown'] = Campusidp::IDP_HINT_BUTTONS_LIMIT;

            for ($i = 0; $i < count($idpsAsConfigItems->items); $i++) {
                $hintComponentConfig['identities'][$i] = [
                    'name' => $idpsAsConfigItems->items[$i]->text,
                    'logo' => $idpsAsConfigItems->items[$i]->image,
                    'upstream_idp' => $idpsAsConfigItems->items[$i]->idpentityid,
                ];
            }
        }
    }
}

if (array_key_exists('source', $_POST)) {
    if (array_key_exists('searchbox', $_POST)) {
        $state['saml:idp'] = $_POST['searchbox'];

        if (
            !empty($metadata[$_POST['searchbox']]) &&
            !empty($wayfConfig['components'][$_POST['componentIndex']]) &&
            $wayfConfig['components'][$_POST['componentIndex']]['name'] === 'searchbox'
        ) {
            $prevIdps = Campusidp::getCookie(Campusidp::COOKIE_PREVIOUS_IDPS) === null ?
                [] :
                json_decode(
                    gzinflate(base64_decode(Campusidp::getCookie(Campusidp::COOKIE_PREVIOUS_IDPS), true)),
                    true
                );

            if (!Campusidp::isIdpInCookie($prevIdps, $_POST['searchbox'])) {
                $chosenIdp = [];
                $chosenIdp['entityid'] = $_POST['searchbox'];
                $chosenIdp['name'] = $metadata[$_POST['searchbox']]['name'];
                $chosenIdp['img'] = $wayfConfig['components'][$_POST['componentIndex']]['logos'][$_POST['searchbox']]
                    ?? Campusidp::getMostSquareLikeImg($metadata[$_POST['searchbox']]);
                $chosenIdp['index'] = $_POST['componentIndex'];


                $prevIdps[] = $chosenIdp;

                while (strlen(base64_encode(gzdeflate(json_encode($prevIdps)))) > 4093) {
                    array_shift($prevIdps);
                }

                Campusidp::setCookie(Campusidp::COOKIE_PREVIOUS_IDPS, base64_encode(gzdeflate(json_encode($prevIdps))));
            }
        }

        Campusidp::delegateAuthentication($_POST['source'], $state);
    } elseif (array_key_exists('idpentityid', $_POST)) {
        $state['saml:idp'] = $_POST['idpentityid'];
        Campusidp::delegateAuthentication($_POST['source'], $state);
    } elseif (array_key_exists('username', $_POST) && array_key_exists('password', $_POST)) {
        if (empty($_POST['username']) || empty($_POST['password'])) {
            $_REQUEST['wrongUserPass'] = true;
        } else {
            if (!empty($_POST['dont_remember_me']) && $_POST['dont_remember_me'] === 'Yes') {
                $state['DontRememberMe'] = true;
            }
            if (!empty($_POST['remember_me']) && $_POST['remember_me'] === 'Yes') {
                $state['RememberMe'] = true;
            }

            Campusidp::delegateAuthentication($_POST['source'], $state);
        }
    }
}

if (!empty($wayfConfig['footer']['format']) && $wayfConfig['footer']['format'] === 'markdown') {
    $converter = new CommonMarkConverter();

    foreach ($wayfConfig['footer']['sections'] as $key => $value) {
        if (is_array($value)) {
            foreach ($wayfConfig['footer']['sections'][$key] as $subKey => $subValue) {
                $wayfConfig['footer']['sections'][$key][$subKey] = $converter->convertToHtml($subValue)->getContent();
            }
        } else {
            $wayfConfig['footer']['sections'][$key] = $converter->convertToHtml($value)->getContent();
        }
    }
}

$idps = null;
if (!empty($_POST['q'])) {
    $ch = curl_init();

    curl_setopt(
        $ch,
        CURLOPT_URL,
        Module::getModuleURL(
            'campusmultiauth/idpSearch.php?q=' . $_POST['q']
            . '&index=' . $_POST['componentIndex']
            . '&language=' . $_POST['currentLanguage']
        )
    );
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    $idps = json_decode(curl_exec($ch));
    curl_close($ch);
}

// <timeout dialog>
$timeoutDialogConfig =
    Configuration::getConfig('module_campusmultiauth.php')->getConfigItem('timeout_dialog');

if (!empty($timeoutDialogConfig)) {
    $restartUrl = '#';

    if (isset($state['SPMetadata']['RelayState'])) {
        $rsUrl = filter_var(
            $state['SPMetadata']['RelayState'],
            FILTER_VALIDATE_URL
        );
        if ($rsUrl !== false) {
            $restartUrl = $rsUrl;
        }
    }

    if (isset($state['saml:RelayState'])) {
        $rsUrl = filter_var(
            $state['saml:RelayState'],
            FILTER_VALIDATE_URL
        );

        if ($rsUrl !== false) {
            $rs = parse_url($rsUrl);
            $sp = $state['SPMetadata']['AssertionConsumerService'];
            if (is_array($sp) && isset($sp[0])) {
                $sp = $sp[0];
            }
            if (is_array($sp) && isset($sp['Location'])) {
                $sp = $sp['Location'];
            }
            if (is_string($sp)) {
                $sp = parse_url($sp);
                if ($rs['scheme'] === $sp['scheme'] && $rs['host'] === $sp['host']) {
                    $restartUrl = $rsUrl;
                }
            }

            // use login URL instead of redirecting to OIDC
            $restartUrl = Campusidp::useLoginURL($state, $timeoutDialogConfig, $restartUrl);
        }
    }
}
// </timeout dialog>

$globalConfig = Configuration::getInstance();
$t = new Template($globalConfig, 'campusmultiauth:selectsource.php');

array_key_exists('wrongUserPass', $_REQUEST) ? $t->data['wrongUserPass'] = true : $t->data['wrongUserPass'] = false;
$t->data['authstate'] = $authStateId;
$t->data['currentUrl'] = htmlentities($_SERVER['PHP_SELF']);
$t->data['wayf_config'] = $wayfConfig;
$t->data['rememberme_enabled'] = Configuration::getInstance()->getBoolean('session.rememberme.enable', false);
$t->data['rememberme_checked'] = Configuration::getInstance()->getBoolean('session.rememberme.checked', false);
$t->data['muni_jvs'] = ($wayfConfig['css_framework'] ?? 'bootstrap5') === 'muni_jvs';
$t->data['idps'] = $idps;
$t->data['no_js_display_index'] = !empty($_POST['componentIndex']) ? $_POST['componentIndex'] : null;
$t->data['user_pass_source_name'] = $state[Campusidp::USER_PASS_SOURCE_NAME];
$t->data['sp_source_name'] = $state[Campusidp::SP_SOURCE_NAME];

if (!empty($hintedIdps)) {
    $t->data['idpsToShow'] = $hintedIdps;

    if (empty($hintComponentConfig)) {
        if ($sendParsedHint) {
            $t->data['idphint'] = $hintedIdps;
            $searchboxesToDisplay = Campusidp::findSearchboxesToDisplay($hintedIdps, $wayfConfig, null);
        } else {
            if (!empty($state['aarc_discovery_hint'])) {
                $t->data['aarc_discovery_hint'] = $state['aarc_discovery_hint'];
            }
            if (!empty($state['aarc_discovery_hint_uri'])) {
                $t->data['aarc_discovery_hint_uri'] = $state['aarc_discovery_hint_uri'];
            }

            $searchboxesToDisplay = Campusidp::findSearchboxesToDisplay(null, $wayfConfig, $state);
        }

        $individualIdentitiesToDisplay = Campusidp::findIndividualIdentitiesToDisplay($hintedIdps, $wayfConfig);

        $t->data['searchboxes_to_display'] = $searchboxesToDisplay;
        $t->data['individual_identities_to_display'] = $individualIdentitiesToDisplay;
        $t->data['or_positions'] = Campusidp::getOrPositions(
            $searchboxesToDisplay,
            $individualIdentitiesToDisplay,
            $hintedIdps,
            $wayfConfig
        );
    } else {
        $t->data['hint_component_config'] = $hintComponentConfig;
    }
}

if (isset($restartUrl)) {
    $t->data['restart_url'] = $restartUrl;
    $t->data['refresh_dialog_timeout'] = $timeoutDialogConfig->getInteger('refresh.dialog.timeout', 5 * 60);
}

$t->data['searchbox_indexes'] = json_encode(array_values(array_filter(array_map(function ($config, $index) {
    return $config['name'] === 'searchbox' ? $index : null;
}, $wayfConfig['components'], array_keys($wayfConfig['components'])), function ($a) {
    return $a !== null;
})));
$currentLanguage = $t->getTranslator()
    ->getLanguage()
    ->getLanguage();
$t->data['searchbox_placeholders'] = json_encode(array_map(function ($config) use ($currentLanguage) {
    if ($config['name'] !== 'searchbox') {
        return null;
    }
    if (isset($config['placeholder'][$currentLanguage])) {
        return $config['placeholder'][$currentLanguage];
    }
    if (!empty($config['placeholder']) && is_array($config['placeholder'])) {
        return reset($config['placeholder']);
    }
    if (!empty($config['placeholder'])) {
        return $config['placeholder'];
    }
    return null;
}, $wayfConfig['components']));

if (Campusidp::getCookie(Campusidp::COOKIE_PREVIOUS_IDPS) === null) {
    $t->data['prev_idps'] = [];
} else {
    $t->data['prev_idps'] = json_decode(
        gzinflate(base64_decode(Campusidp::getCookie(Campusidp::COOKIE_PREVIOUS_IDPS), true))
    );
}

$rememberMe = new RememberMe();

$dontRemember = filter_input(
    INPUT_COOKIE,
    $rememberMe->getDontCookieName(),
    FILTER_DEFAULT,
    [
        'default' => '',
    ]
) === 'Yes';

$t->data['dontRemember'] = $dontRemember;

$config = Configuration::getOptionalConfig('module_campusmultiauth.php')->getConfigItem('remember_me', []);
$imagesConfig = $config->getConfigItem('security_images', []);

// verify cookie (if present), update counter and cookie

if (
    empty($t->data['forceUsername'])
    && !empty($_GET[RememberMe::CLEAR_USERNAME_PARAM])
) {
    $t->data['username'] = '';
    $t->data['userInfo'] = false;
    $rememberMe->deleteCookie();
}

$t->data['userInfo'] = $dontRemember ? false : $rememberMe->getUserInfo();

if ($t->data['userInfo']) {
    if (empty($t->data['username']) || $t->data['userInfo']['username'] === $t->data['username']) {
        $t->data['username'] = $t->data['userInfo']['username'];
        $showFreshImage = $imagesConfig->getBoolean('showFreshImage', false);

        if ($showFreshImage && (($t->data['userInfo']['security_image'] ?? true) !== false)) {
            $t->data['securityImage'] = Utils::getSecurityImageOfUser($t->data['userInfo']['username']);
        } elseif (!$showFreshImage && !empty($t->data['userInfo']['security_image'])) {
            $t->data['securityImage'] = $t->data['userInfo']['security_image'];
        }

        if ($showFreshImage && (($t->data['userInfo']['alternative_text'] ?? true) !== false)) {
            $t->data['alternativeText'] = Utils::getAlternativeTextOfUser($t->data['userInfo']['username']);
        } elseif (!$showFreshImage && !empty($t->data['userInfo']['alternative_text'])) {
            $t->data['alternativeText'] = $t->data['userInfo']['alternative_text'];
        }

        $pictureDir = $imagesConfig->getString('pictureDir', null);
        if (!empty($t->data['securityImage']) && $pictureDir !== null) {
            $pictureDataSrc = $t->data['securityImage'];
            if (preg_match('~^data:image/(png|jpeg|gif);base64,(.*)$~', $pictureDataSrc, $matches)) {
                list(, $pictureType, $pictureContent) = $matches;
                $pictureContent = base64_decode($pictureContent, true);
                if ($pictureContent !== false) {
                    $pictureFileName = sprintf(
                        '%s-%s.%s',
                        $t->data['username'],
                        hash('sha256', $imagesConfig->getString('securityImageSalt') . $t->data['username']),
                        $pictureType
                    );
                    if (!file_exists($pictureDir) && !mkdir($pictureDir, 0755, true)) {
                        throw new \Error('Folder for security images does not exist and could not be created.');
                    }
                    $pictureFilePath = rtrim($pictureDir, '/') . '/' . $pictureFileName;
                    file_put_contents($pictureFilePath, $pictureContent);
                    if (image_type_to_mime_type(exif_imagetype($pictureFilePath)) !== 'image/' . $pictureType) {
                        Logger::warning('Invalid security image, type mismatch: ' . $t->data['securityImage']);
                        unlink($pictureFilePath);
                    } else {
                        $t->data['securityImage'] = sprintf(
                            '%s/%s',
                            rtrim($imagesConfig->getString('pictureBaseURL'), '/'),
                            $pictureFileName
                        );
                    }
                }
            }
        }
    } elseif ($t->data['username'] !== $t->data['userInfo']['username']) {
        $t->data['userInfo'] = false;
    }
}

if (!empty($t->data['username'])) {
    $t->data['autofocus'] = 'password';
} else {
    $t->data['autofocus'] = 'username';
}

$t->data['uidName'] = $config->getString('uidName', '');

if ($t->data['userInfo'] !== false) {
    $t->data['accessTarget'] = 'remembered-name';
}

$t->data['differentUsername'] = RememberMe::getOtherUsernameLink($authStateId);

$t->send();
exit();
