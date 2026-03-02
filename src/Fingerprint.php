<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth;

abstract class Fingerprint
{
    abstract public function getValue();
}
