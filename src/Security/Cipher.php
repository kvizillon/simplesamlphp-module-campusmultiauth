<?php

namespace SimpleSAML\Module\campusmultiauth\Security;

interface Cipher
{
    public function __construct();

    /**
     * Encrypt the data.
     *
     * @return string
     */
    public function encrypt(string $data);

    /**
     * Decrypt the data.
     *
     * @return might return false if data is currupted, string otherwise
     */
    public function decrypt(string $data);
}
