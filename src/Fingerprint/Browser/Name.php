<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth\Fingerprint\Browser;

class Name extends \SimpleSAML\Module\campusmultiauth\Fingerprint\Browser
{
    protected function getProperty($ua)
    {
        return $ua->browser();
    }
}
