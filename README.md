# simplesamlphp-module-campusmultiauth

![maintenance status: end of life](https://img.shields.io/maintenance/end%20of%20life/2024)

This project has reached end of life, which means no new features will be added. Security patches and important bug fixes ended in May 2024. Check out [Apereo CAS](https://apereo.github.io/cas/) and [ProxyIdP GUI](https://gitlab.ics.muni.cz/perun/perun-proxyidp/proxyidp-gui) instead.

## Description

Thanks to this module, you can use a saml:SP authentication source together with another authentication source providing basic auth (discovery service and login form are displayed on a single page).

## Theme configuration

For proper function, this modules requires the usage of the included theme called `campus`. Modify `config/config.php` to include these lines:

```
'theme.use' => 'campusmultiauth:campus',
'usenewui' => true,
```

You may also try to use a different Bootstrap 5 based theme, but compatibility is not guaranteed.

## Authsources configuration

To achieve this, you need to define and configure an authentication source in your authsources.php file. An example configuration is shown below:

    'campus-idp' => [
        'campusmultiauth:Campusidp',

        'userPassSource' => [
            'name' => 'campus-userpass',
            'AuthnContextClassRef' => []
        ],

        'spSource' => [
            'name' => 'default-sp',
            'AuthnContextClassRef' => []
        ]
    ],

The following configuration options are available:

`campusmultiauth:campusidp` defines which module and authentication source to use. This is the only mandatory option.

`userPassSource` is an authentication source to use to authentication with a username and password. For easy integration with any identity provider supporting [ECP](http://docs.oasis-open.org/security/saml/Post2.0/saml-ecp/v2.0/saml-ecp-v2.0.html), see [simplesamlphp-module-campususerpass](https://gitlab.ics.muni.cz/perun/perun-proxyidp/simplesamlphp-module-campususerpass). If the name is not set, `campus-userpass` is used as a default option.

`spSource` is an authentication source to use to authentication with an external identity provider. If the name is no set, `default-sp` is used as a default option.

Of course, both authsources must be defined in authsources.php file. When the configuration is done, the next step is to open `saml20-idp-hosted.php` file and set your authsource (`campus-idp` in our example) as an authentication source (`auth` option).

## Login page configuration

The second part of the configuration is setting up the login page itself. To configure the login page, you need to create a new configuration file `module_campusmultiauth.php`. In this module, there is an example configuration available at `config-templates/module_campusmultiauth.php`. In configuration file, there are following options available:

`css_framework` - if set to `muni_jvs`, the login page displays in MUNI framework. Otherwise, Bootstrap 5 is used.

`muni_faculty` - relevant only if the `css_framework` is set to `muni_jvs`. The value can be set to a concrete faculty which results in the change of framework's main colors. You can find the list of faculties and their colors [here](https://sablony.muni.cz/muniweb/tpl/d-02-barvy.html).

`logo` - URL to a main institution logo which is displayed in top of the login page.

`name` - used as an alternative text for the logo.

`languages` - map of supported languages. The format is language code by [ISO-639-1](https://en.wikipedia.org/wiki/List_of_ISO_639-1_codes) as the key and whole language name as the value (e.g. `'en' => 'English'`). If not defined, the only supported language is English.

`footer` - defines a footer of the login page. For further instructions how to configure a footer, see the [Footer](#footer) section below.

`components` - list of components. This is the main part of the login page. Each component represents an authentication possibility for the user. For further instructions how to configure components, see the [Components](#components) section below.

### Footer

Footer defines the bottom of the login page. If it is not set, the footer is empty. To allow you to adapt the footer to your organisation's look, the `footer` option is designed as a map with the following possible options:

`sections` - list of sections. Each section represents a column in the footer's grid. It means that, in case of Bootstrap 5, the count of sections **_must_** divide 12. If you decide to use MUNI framework, the count of sections **_must_** divide 4. Each section then contains string with HTML, Markdown or simple text, based on the `format` option. If you want to add localization, you can define `sections` as a map with language codes as keys. Values are then lists of sections with localized texts. In that case, you **_must_** define sections for **_all_** supported languages.

`format` - defines the format of sections. You can set it to `HTML` or `markdown`. If not set, the sections are printed as a simple text.

### Components

The main part of the login page. The `components` option is designed as a list, where each element represents one component. A component is a map with several possible options. The most important option is `name`. It defines the component's type. There are three possible values for `name`: `local_login`, `searchbox` and `individual_identities`.

#### local_login

This component represents a form with username and password. It can be used only once. For the Remember me functionality, see below. In the module configuration, there are following options:

`username_label` - this is displayed as a label above input for the username. If you want to add localization, you can write the value as a map with language codes as keys and localized strings as values. If current language is not found in keys, the **_first one_** is used instead. If not set at all, it displays a default value.

`username_placeholder` - this is displayed as a placeholder in the input for the username. If you want to add localization, you can write the value as a map with language codes as keys and localized strings as values. If current language is not found in keys, the **_first one_** is used instead. If not set at all, it displays a default value.

`password_label` - this is displayed as a label above input for the password. If you want to add localization, you can write the value as a map with language codes as keys and localized strings as values. If current language is not found in keys, the **_first one_** is used instead. If not set at all, it displays a default value.

`password_placeholder` - this is displayed as a placeholder in the input for the password. If you want to add localization, you can write the value as a map with language codes as keys and localized strings as values. If current language is not found in keys, the **_first one_** is used instead. If not set at all, it displays a default value.

`entityid` - entityid of the identity provider. Needed for idp hinting.

`priority` - can be set to `primary`, default value is `secondary`. It should be primary if you want users to use this component if they are able to.

`end_col` - on a desktop, components are divided to two columns. If you want this component to be the last one in the first column, set this option to `true`.

#### searchbox

Thanks to the searchbox you can search between all included identity providers. This component may be used multiple times.

`title` - text displayed above the component. If you want to add localization, you can write the value as a map with language codes as keys and localized strings as values. If current language is not found in keys, the **_first one_** is used instead. If not set at all, it displays a default value.

`placeholder` - text displayed as a placeholder in the searchbox. If you want to add localization, you can write the value as a map with language codes as keys and localized strings as values. If current language is not found in keys, the **_first one_** is used instead. If not set at all, it displays a default value.

`filter` - if you want to display just part of identity providers available in the metadata, you can use this option. If not set, all identity providers from the metadata are included. Otherwise, identity providers to display are chosen based on the [aarc_discovery_hint](https://docs.google.com/document/d/1rHKGzPsjkbqKHxsPnCb0itRLXLtqm-A8CZ5fzzklaxc/edit) logic. However, there are some differences. The content of this option is already decoded (which means it is in the PHP format, not the JSON). Also, you can use the `entityid` claim (instead of `entity_category` / `assurance_certification` / `registration_authority`) to include or exclude specific identity providers. You can find a sample use of the `entityid` claim in [module_campusmultiauth.php](https://gitlab.ics.muni.cz/perun/perun-proxyidp/simplesamlphp-module-campusmultiauth/-/blob/main/config-templates/module_campusmultiauth.php) config template.

`priority` - can be set to `primary`, default value is `secondary`. It should be primary if you want users to use this component if they are able to.

`end_col` - on a desktop, components are divided to two columns. If you want this component to be the last one in the first column, set this option to `true`.

#### individual_identities

Here you can specify some identity providers to display them as a list of buttons. This components may be used multiple times.

`title` - text displayed above the component. If you want to add localization, you can write the value as a map with language codes as keys and localized strings as values. If current language is not found in keys, the **_first one_** is used instead. If not set at all, it displays a default value.

`priority` - can be set to `primary`, default value is `secondary`. It should be primary if you want users to use this component if they are able to.

`end_col` - on a desktop, components are divided to two columns. If you want this component to be the last one in the first column, set this option to `true`.

`number_shown` - how many buttons to show. If the count of specified identity providers is higher than this number, then part of identity providers will be hidden and replaced with button which shows them all on click.

`identities` - list of identity providers to display as buttons. Each identity provider has some configuration options available. For further information, see the [identities](#identities) section below.

`logos` - optional map with keys of entity IDs and values of URLs to logos. This option can be used to override logos for some identity providers, which are expected to be used often but do not have a suitable (square) logo in their metadata.

##### identities

Each identity is a map with the following possible options:

`upstream_idp` - identity provider's identifier (e.g. entityid)

`name` - identity provider's name, displayed as a text inside the button. If you want to add localization, you can write the value as a map with language codes as keys and localized strings as values. If current language is not found in keys, the **_first one_** is used instead.

`logo` - identity provider's logo, displayed on a left side of the button as a square.

`background_color` - background around the logo. Defined as a [CSS color value](https://developer.mozilla.org/en-US/docs/Web/CSS/color_value).

### Remember me and security images

You can add a `remember_me` section to your configuration file to add some convenience and anti-phishing features to your `local_login` component.

#### Remember me

To enable the `remember_me` checkbox and optionally set it as checked by default, configure `session.rememberme.enable` and `session.rememberme.checked` options in the `config.php` file. If you want to make session longer if the checkbox is checked, use the [ExtendIdPSession](https://github.com/simplesamlphp/simplesamlphp/blob/v1.19.6/modules/core/lib/Auth/Process/ExtendIdPSession.php) auth proc filter. It is highly recommended to also set a [session checking function](https://simplesamlphp.org/docs/1.19/simplesamlphp-advancedfeatures.html#session-checking-function).

You can store info about the user in the cookie, including a counter of user's visits of the login page, which is compared to the value stored in the database. This can help to detect some suspicious behaviour. To enable this feature, you have to enable the `remember_me` checkbox mentioned above and add the `RememberMe` auth proc filter. Then set the following options in the `remember_me` section of the configuration file:

`nameAttr` - a name of the attribute with the user's name. Has to be present in the `$request['attributes']` in the Authproc filter. The default value is `displayName`.

`store` - a database configuration, used as an argument for the `SimpleSAML\Database::getInstance()` method.

`tokens_table` - a name of the database table where user tokens with counters are stored. The default value is `cookie_counter`.

`signature_key` - a key used for signing JWTs.

`encryption_key` - a key used for encrypting JWTs.

`signature_algorithm` - a signature algorithm, default `HS512`.

`encryption_algorithm` - an encryption algorithm, default `A256GCM`.

`keywrap_algorithm` - a keywrap algorithm, default `A256GCMKW`.

`uid_attribute` - a user's identifier attribute, default `uid`.

`cipherClass` - an implementation of `SimpleSAML\Module\campusmultiauth\Security\Cipher`, default `SimpleSAML\Module\campusmultiauth\Security\JWTCipher`.

`uidName` - value of this option is displayed before the user's uid attribute value, default value is empty string (which will display nothing).

`cookieName` - a cookie name where the info about user is stored, default `campus_userinfo`.

`dontCookieName` - if user decides not to remember login on current device, this decision will also be stored into a cookie. Value of this option is used as the name of this cookie. The default value is `campus_dont_remember`.

#### Security images

In addition to the remember me function, you can turn on security images. Image specific to each user will be shown on the login page if set, which proves it is not a phishing site. To configure this feature, you need to add `security_images` to the `remember_me` section and set:

`showFreshImage` - if set to true, the security image is fetched everytime user access the login page. Otherwise, it is stored in the cookie. Default `false`.

`storageClass` - an implementation of `SimpleSAML\Module\campusmultiauth\Data\Storage`, default `SimpleSAML\Module\campusmultiauth\Data\DatabaseStorage`.

`pictureStorage` - if some other storage than `SimpleSAML\Module\campusmultiauth\Data\DatabaseStorage` is used (e.g. `SimpleSAML\Module\campusmultiauth\Data\PerunStorage`), this is the place for the configuration of the storage.

`security.cookie.path` - cookie path.

`security.cookie.samesite` - cookie SameSite.

`pictureDir` - if set, the security image is stored in this directory instead of the cookie. The cookie than contains only a link to the picture. Also, if this option is enabled, `securityImageSalt` and `pictureBaseURL` are mandatory. Default `null`.

`securityImageSalt` - a salt which is used in the filename of the picture if the `pictureDir` is on.

`pictureBaseURL` - base URL to the pictures if the `pictureDir` is on.

`pictures_table` - name of the table with security images, default `security_image`.

`texts_table` - default `alternative_text`. You can also add an alternative text to images. User can specify his/her own text, so this is an additional antiphishing feature. If user does not have the alternative text set, the alt is an empty string. In case he/she does not have the image set, this text will be displayed instead of it.

## Hinting

To help the user choose the right institution to log in, this module supports following standards:

### [aarc_discovery_hint (aarc_discovery_hint_uri)](https://docs.google.com/document/d/1rHKGzPsjkbqKHxsPnCb0itRLXLtqm-A8CZ5fzzklaxc/edit)

A service provider can choose which identity provider(s) should user use. If there is only one option, the user is redirected directly to the identity provider. Otherwise, user chooses from identity providers sent in the `aarc_discovery_hint` parameter. In addition to this standard, service provider can use the `entityid` claim (instead of `entity_category` / `assurance_certification` / `registration_authority`) to include or exclude specific identity providers.

### [aarc_idp_hint](https://zenodo.org/record/4596667/files/AARC-G061-A_specification_for_IdP_hinting.pdf)

A service provider can choose which identity provider should user use, he/she then skips the login page and is redirected to the targeted identity provider.

### [idphint](https://aarc-project.eu/wp-content/uploads/2019/04/AARC-G049-A_specification_for_IdP_hinting-v6.pdf)

A service provider can choose which identity provider(s) should user use. If there is only one option, the user is redirected directly to the identity provider. Otherwise, user chooses from identity providers sent in idphint parameter.

## Deployment

The easiest way is to use a docker container, which includes this module together with SimpleSAMLphp and PHP-FPM.

If you want to use non-SAML providers (e.g. OAuth or OIDC), you need to provide a bridge. There are multiple ways possible:

- deploy a proxy (e.g. [SATOSA](https://github.com/IdentityPython/SATOSA)) which translates other authentication protocols to SAML
- use SimpleSAMLphp's [OIDC module](https://github.com/simplesamlphp/simplesamlphp-module-oidc/) for OIDC (e.g. Google)
- use [authoauth2 module](https://github.com/cirrusidentity/simplesamlphp-module-authoauth2) for OAuth (LinkedIn, ORCid, GitHub...)

### Content security policy

This module uses no third party CSS, JavaScript or fonts, everything is bundled. The only inline CSS is used when you configure `background_color` in the `individual_identities` component.

## External frameworks

This module uses some external frameworks / libraries. You can find a complete list of them here:

- [Bootstrap](https://getbootstrap.com/)
- [MUNI framework](https://sablony.muni.cz/muniweb/tpl/muni-framework.html)
- [Selectize](https://selectize.dev/)
- [Font Awesome](https://fontawesome.com/)
