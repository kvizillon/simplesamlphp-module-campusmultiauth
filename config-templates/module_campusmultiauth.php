<?php

/**
 * An example configuration of the login page
 */

declare(strict_types=1);

$config = [
    'components' => [
        [
            'name' => 'local_login',
            'end_col' => true,
            'priority' => 'primary',
            'username_label' => [
                'cs' => 'UČO',
                'en' => 'Personal ID (učo)',
            ],
            'username_placeholder' => [
                'cs' => 'UČO',
                'en' => 'Personal ID',
            ],
            'password_label' => [
                'cs' => 'Primární heslo',
                'en' => 'Primary password',
            ],
            'password_placeholder' => [
                'cs' => 'Heslo',
                'en' => 'Password',
            ],
            'entityid' => 'https://idp2.ics.muni.cz/idp/shibboleth',
        ],
        [
            'name' => 'searchbox',
            'title' => [
                'cs' => 'Přihlášení přes jinou instituci',
                'en' => 'Log in via another institution',
            ],
            'placeholder' => [
                'cs' => 'Vyhledejte např. CEITEC',
                'en' => 'Search e.g. CEITEC',
            ],
            'filter' => [
                'exclude' => [
                    'any_of' => [
                        0 => [
                            'entityid' => [
                                'equals' => 'https://www.vutbr.cz/SSO/saml2/idp'
                            ],
                        ],
                        1 => [
                            'entityid' => [
                                'equals' => 'https://idp2.ics.muni.cz/idp/shibboleth'
                            ],
                        ],
                    ],
                ],
            ],
            'logos' => [
                'https://idp2.ics.muni.cz/idp/shibboleth' => 'https://id.muni.cz/android-chrome-192x192.png',
            ],
        ],
        [
            'name' => 'individual_identities',
            'title' => [
                'cs' => 'Přihlášení přes cizí identitu',
                'en' => 'Log in via institution or social network',
            ],
            'number_shown' => 3,
            'identities' => [
                0 => [
                    'name' => [
                        'en' => 'VUT en',
                        'cs' => 'VUT cs',
                    ],
                    'logo' => 'https://example.com/logos/vut.png',
                    'upstream_idp' => 'https://www.vutbr.cz/SSO/saml2/idp',
                    'background_color' => '#990000',
                ],
                1 => [
                    'name' => 'UTB',
                    'logo' => 'https://example.com/logos/utb.png',
                    'upstream_idp' => 'https://login.bbmri-eric.eu/idp/',
                ],
                2 => [
                    'name' => 'Linkedin',
                    'logo' => 'https://example.com/logos/linkedin.png',
                    'upstream_idp' => 'https://login.elixir-czech.org/linkedin-idp/',
                ],
            ],
        ],
    ],
    'css_framework' => 'muni_jvs',
    'logo' => 'https://example.com/logos/muni2.png',
    'name' => 'MUNI',
    'muni_faculty' => 'econ',
    'footer' => [
        'format' => 'HTML',
        'sections' => [
            'cs' => [
                0 => '<h5>Máte problém s přihlášením?</h5>',
                1 => '<div>Službu Autentizační brána zajišťuje Ústav výpočetní techniky.</div>',
            ],
            'en' => [
                0 => '<h5>Having trouble logging in?</h5>',
                1 => '<div>The Authentication Gateway service is provided by the Institute of Computer Science.</div>',
            ],
        ],
    ],
    'languages' => [
        'cs' => 'Čeština',
        'en' => 'English',
    ],
    'timeout_dialog' => [
        'ldap.hostname' => '',
        'ldap.username' => '',
        'ldap.password' => '',
        'ldap.basedn' => '',
        'ldap.timeout' => 0,
        //    'refresh.dialog.timeout' => 5 * 60,
        //    'identifier.attr.name' => 'OIDCClientID',
        //    'url.attr.name' => 'rploginurl',
    ],
    'remember_me' => [
        'security_images' => [
            //    'pictureDir' => '',
            //    'showFreshImage' => false,
            //    'securityImageSalt' => '',
            //    'pictureBaseURL' => '',
            //    'pictures_table' => '',
            //    'pictureStorage' => [
            //        'ldap.hostname' => '',
            //        'ldap.port' => 0,
            //        'ldap.enable_tls' => false,
            //        'ldap.debug' => false,
            //        'ldap.referrals' => false,
            //        'ldap.timeout' => 0,
            //        'ldap.username' => '',
            //        'ldap.password' => '',
            //        'ldap.basedn' => '',
            //        'search.filter' => '',
            //        'attribute' => '',
            //        'alternative_text_attribute' => '',
            //    ],
        ],
        //    'uidName' => '',
        //    'cookieName' => '',
        //    'nameAttr' => '',
        //    'cipherClass' => '',
        //    'storageClass' => '',
        //    'security.cookie.path' => '',
        //    'security.cookie.samesite' => '',
        'store' => [
            'database.dsn' => 'dsn',
            'database.username' => 'username',
            'database.password' => 'password',
        ],
        'tokens_table' => 'tokens_table',
        'signature_key' => [
            'kty' => 'oct',
            'k' => 'tCUdnHNp8xH/egDmzwxEkI1BzknCJmAt1khoQsfm9+FNSwIwq9ILN6GYBWjEAoykttrXx5aI/lRdyyGjheRj/g==',
        ],
        'encryption_key' => [
            'kty' => 'oct',
            'k' => 'BdateloTM7i01lo9L0bfctTJ/2B9E2VCfrTqdhqxilg=',
        ],
        //    'uid_attribute' => '',
        //    'signature_algorithm' => '',
        //    'encryption_algorithm' => '',
        //    'keywrap_algorithm' => '',
    ],
];
