<?php

declare(strict_types=1);

use SimpleSAML\Module\campusmultiauth\Auth\Source\Campusidp;

$prevIdps = Campusidp::getCookie(Campusidp::COOKIE_PREVIOUS_IDPS) === null ?
    [] :
    json_decode(gzinflate(base64_decode(Campusidp::getCookie(Campusidp::COOKIE_PREVIOUS_IDPS), true)), true);

$entityid = $_POST['entityid'];

foreach ($prevIdps as $index => $idp) {
    if ($idp['entityid'] === $entityid) {
        unset($prevIdps[$index]);
    }
}

Campusidp::setCookie(Campusidp::COOKIE_PREVIOUS_IDPS, base64_encode(gzdeflate(json_encode($prevIdps))));
