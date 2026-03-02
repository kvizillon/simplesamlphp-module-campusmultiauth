<?php

declare(strict_types=1);

use SimpleSAML\Module;

$this->data['header'] = $this->t('{privacyidea:privacyidea:login_title_challenge}');

$this->data['head'] .= '<link rel="stylesheet" href="'
    . htmlspecialchars(Module::getModuleUrl('privacyidea/css/loginform.css'), ENT_QUOTES)
    . '" media="screen" />';
$this->data['head'] .= '<link rel="stylesheet" href="'
    . htmlspecialchars(Module::getModuleUrl('campusmultiauth/assets/privacyidea.css'), ENT_QUOTES)
    . '" media="screen" />';

$this->includeAtTemplateBase('includes/header.php');

// Prepare error case to show it in UI if needed
if ($this->data['errorCode'] !== null) {
    ?>

    <div class="message message--common message--common-error" role="alert">
        <a href="#" class="message__close icon icon-times" title="<?php echo $this->t('{campusmultiauth:close}'); ?>">
            <span class="vhide"><?php echo $this->t('{campusmultiauth:close}'); ?></span>
        </a>
        <span class="message__icon icon icon-exclamation-triangle"></span>
        <h2 class="message__title"><?php echo $this->t('{login:error_header}'); ?></h2>
        <p class="message__desc">
    <?php
    echo htmlspecialchars(
        sprintf('%s%s: %s', $this->t(
            '{privacyidea:privacyidea:error}'
        ), $this->data['errorCode'] ? (' ' . $this->data['errorCode']) : '', $this->data['errorMessage'])
    ); ?>
        </p>
    </div>

    <?php
}  // end of errorcode
?>

    <div class="container">
        <div class="login">
            <form action="FormReceiver.php" method="POST" id="piLoginForm" name="piLoginForm" class="loginForm">
                <div class="form-panel first valid" id="gaia_firstform">
                    <div class="slide-out ">
                        <div class="input-wrapper focused">
                            <div class="identifier-shown grid">
                                <?php if ($this->data['webauthnAvailable']) { ?>
                                <div class="grid__cell size--m--2-4">
                                    <h2><?php echo $this->t('{privacyidea:privacyidea:webauthn}'); ?></h2>
                                    <p id="message" role="alert"><?php
                                        $messageOverride = $this->data['messageOverride'] ?? null;
                                    if ($messageOverride === null || is_string($messageOverride)) {
                                        echo htmlspecialchars(
                                            $messageOverride ?? $this->data['message'] ?? '',
                                            ENT_QUOTES
                                        );
                                    } elseif (is_callable($messageOverride)) {
                                        echo call_user_func($messageOverride, $this->data['message'] ?? '');
                                    }
                                    ?></p>
                                    <p>
                                        <button id="useWebAuthnButton" name="useWebAuthnButton"
                                          class="btn btn-primary btn-s" type="button">
                                            <span><?php echo $this->t('{privacyidea:privacyidea:webauthn}'); ?></span>
                                        </button>
                                    </p>
                                </div>
                                <?php } ?>

                                <?php if ($this->data['otpAvailable'] ?? true) { ?>
                                <div class="grid__cell size--m--2-4">
                                    <h2><?php echo $this->t('{privacyidea:privacyidea:otp}'); ?></h2>
                                    <p><?php echo $this->t('{campusmultiauth:otp_help}'); ?></p>
                                    <div class="form-inline">
                                        <p class="size--m--4-4 size--l--6-12">
                                            <label for="otp" class="sr-only">
                                                <?php echo $this->t('{privacyidea:privacyidea:otp}'); ?>
                                            </label>
                                            <span class="inp-fix">
                                                <input id="otp" name="otp" tabindex="1" value="" class="text inp-text"
                                                autocomplete="one-time-code" type="number" inputmode="numeric"
                                                pattern="[0-9]{6,}" required
                                                placeholder="<?php echo htmlspecialchars($otpHint, ENT_QUOTES); ?>"
                                                <?php if ($this->data['noAlternatives']) {
                                                    echo ' autofocus';
                                                } ?> />
                                            </span>
                                        </p>
                                        <p>
                                            <button id="submitButton" tabindex="1"
                                              class="rc-button rc-button-submit btn btn-primary btn-s nowrap"
                                              type="submit" name="Submit">
                                                <span>
                                                    <?php echo htmlspecialchars(
                                                        $this->t('{login:login_button}'),
                                                        ENT_QUOTES
                                                    ); ?></span>
                                            </button>
                                        </p>
                                    </div>
                                </div>
                                <?php } ?>

                                <!-- Undefined index is suppressed and the default is used for these values -->
                                <input id="mode" type="hidden" name="mode" value="otp"
                                data-preferred="<?php echo htmlspecialchars($this->data['mode'], ENT_QUOTES); ?>"/>

                                <input id="pushAvailable" type="hidden" name="pushAvailable"
                                value="<?php echo ($this->data['pushAvailable'] ?? false) ? 'true' : ''; ?>"/>

                                <input id="otpAvailable" type="hidden" name="otpAvailable"
                                value="<?php echo ($this->data['otpAvailable'] ?? true) ? 'true' : ''; ?>"/>

                                <input id="webAuthnSignRequest" type="hidden" name="webAuthnSignRequest"
                                value='<?php echo htmlspecialchars(
                                    $this->data['webAuthnSignRequest'] ?? '',
                                    ENT_QUOTES
                                ); ?>'/>

                                <input id="u2fSignRequest" type="hidden" name="u2fSignRequest"
                                value='<?php echo htmlspecialchars(
                                    $this->data['u2fSignRequest'] ?? '',
                                    ENT_QUOTES
                                ); ?>'/>

                                <input id="modeChanged" type="hidden" name="modeChanged" value=""/>
                                <input id="step" type="hidden" name="step"
                                value="<?php echo htmlspecialchars(
                                    strval(($this->data['step'] ?? null) ?: 2),
                                    ENT_QUOTES
                                ); ?>"/>

                                <input id="webAuthnSignResponse" type="hidden" name="webAuthnSignResponse" value=""/>
                                <input id="u2fSignResponse" type="hidden" name="u2fSignResponse" value=""/>
                                <input id="origin" type="hidden" name="origin" value=""/>
                                <input id="loadCounter" type="hidden" name="loadCounter"
                                value="<?php echo htmlspecialchars(
                                    strval(($this->data['loadCounter'] ?? null) ?: 1),
                                    ENT_QUOTES
                                ); ?>"/>

                                <!-- Additional input to persist the message -->
                                <input type="hidden" name="message"
                                value="<?php echo htmlspecialchars($this->data['message'] ?? '', ENT_QUOTES); ?>"/>

                                <?php
                                // If enrollToken load QR Code
                                if (isset($this->data['tokenQR'])) {
                                    echo htmlspecialchars(
                                        $this->t('{privacyidea:privacyidea:scan_token_qr}')
                                    ); ?>
                                    <div class="tokenQR">
                                        <?php echo '<img src="' . $this->data['tokenQR'] . '" />'; ?>
                                    </div>
                                    <?php
                                }
                                ?>
                            </div>

                            <?php
                            // Organizations
                            if (array_key_exists('organizations', $this->data)) {
                                ?>
                                <div class="identifier-shown">
                                    <label for="organization">
                                        <?php echo htmlspecialchars($this->t('{login:organization}')); ?>
                                    </label>
                                    <select id="organization" name="organization" tabindex="3">
                                        <?php
                                        if (array_key_exists('selectedOrg', $this->data)) {
                                            $selectedOrg = $this->data['selectedOrg'];
                                        } else {
                                            $selectedOrg = null;
                                        }

                                        foreach ($this->data['organizations'] as $orgId => $orgDesc) {
                                            if (is_array($orgDesc)) {
                                                $orgDesc = $this->t($orgDesc);
                                            }

                                            if ($orgId === $selectedOrg) {
                                                $selected = 'selected="selected" ';
                                            } else {
                                                $selected = '';
                                            }

                                            echo '<option ' . $selected . 'value="' . htmlspecialchars(
                                                $orgId,
                                                ENT_QUOTES
                                            ) . '">' . htmlspecialchars($orgDesc) . '</option>';
                                        } ?>
                                    </select>
                                </div>
                                <?php
                            } ?>
                        </div> <!-- focused -->
                    </div> <!-- slide-out-->
                </div> <!-- form-panel -->
            </form>

            <?php
            // Logout
            if (($this->data['showLogout'] ?? true) && isset($this->data['LogoutURL'])) { ?>
                <p>
                    <a href="<?php echo htmlspecialchars($this->data['LogoutURL']); ?>">
                        <?php echo $this->t('{status:logout}'); ?>
                    </a>
                </p>
            <?php } ?>
        </div>  <!-- End of login -->
    </div>  <!-- End of container -->

<?php
if (!empty($this->data['links'])) {
    echo '<ul class="links">';
    foreach ($this->data['links'] as $l) {
        echo '<li><a href="' . htmlspecialchars($l['href'], ENT_QUOTES) . '">' . htmlspecialchars(
            $this->t($l['text'])
        ) . '</a></li>';
    }
    echo '</ul>';
}
?>

    <script src="<?php echo htmlspecialchars(Module::getModuleUrl('privacyidea/js/pi-webauthn.js'), ENT_QUOTES); ?>">
    </script>

    <script src="<?php echo htmlspecialchars(Module::getModuleUrl('privacyidea/js/u2f-api.js'), ENT_QUOTES); ?>">
    </script>

    <meta id="privacyidea-step" name="privacyidea-step" content="<?php echo $this->data['step']; ?>">

    <meta id="privacyidea-translations" name="privacyidea-translations"
      content="<?php echo htmlspecialchars(json_encode($this->data['translations'])); ?>">

    <script src="<?php echo htmlspecialchars(
        Module::getModuleUrl('privacyidea/js/loginform.js'),
        ENT_QUOTES
    );
                ?>"></script>
    <script src="<?php echo htmlspecialchars(
        Module::getModuleUrl('campusmultiauth/assets/privacyidea.js'),
        ENT_QUOTES
    );
                ?>"></script>

<?php
$this->includeAtTemplateBase('includes/footer.php');
?>
