<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth\Data;

use SimpleSAML\Configuration;
use SimpleSAML\Database;

/**
 * Implementation of Storage using Database.
 */
class DatabaseStorage implements Storage
{
    /**
     * Name of the column with uid.
     */
    private const UID_COL = 'userid';

    /**
     * DB table name for pictures.
     */
    private $pictures_table;

    /**
     * DB table name for texts.
     */
    private $texts_table;

    /**
     * DB table name for tokens.
     */
    private $tokens_table;

    /**
     * Configuration.
     */
    private $config;

    /**
     * Database instance.
     */
    private $db;

    /**
     * @override
     */
    public function __construct()
    {
        $this->config = Configuration::getOptionalConfig('module_campusmultiauth.php')
            ->getConfigItem('remember_me', []);

        $imagesConfiguration = $this->config->getConfigItem('security_images', []);

        $this->db = Database::getInstance($this->config->getConfigItem('store', []));

        $this->pictures_table = $this->db->applyPrefix(
            $imagesConfiguration->getString('pictures_table', 'security_image')
        );
        $this->texts_table = $this->db->applyPrefix(
            $imagesConfiguration->getString('texts_table', 'alternative_text')
        );
        $this->tokens_table = $this->db->applyPrefix(
            $this->config->getString('tokens_table', 'cookie_counter')
        );
    }

    /**
     * @override
     */
    public function getSecurityImageOfUser(string $uid): ?string
    {
        $query = 'SELECT picture FROM ' . $this->pictures_table . ' WHERE ' . self::UID_COL . '=:userid';
        return $this->getSecurityAttributeOfUser($uid, $query);
    }

    /**
     * @override
     */
    public function getAlternativeTextOfUser(string $uid): ?string
    {
        $query = 'SELECT alternative_text FROM ' . $this->texts_table . ' WHERE ' . self::UID_COL . '=:userid';
        return $this->getSecurityAttributeOfUser($uid, $query);
    }

    /**
     * @override
     */
    public function getCookieCounter(string $uid, int $id): ?int
    {
        $query = 'SELECT counter FROM ' . $this->tokens_table
            . ' WHERE ' . self::UID_COL . ' = :userid AND id = :id LIMIT 1';
        $params = [
            'userid' => $uid,
            'id' => $id,
        ];
        $statement = $this->db->read($query, $params);
        $counter = $statement->fetchColumn();
        if ($counter === false) {
            return null;
        }

        return (int) $counter;
    }

    /**
     * @override
     */
    public function increaseCookieCounter(string $uid, ?int $id = null): ?int
    {
        $success = true;
        if ($id === null) {
            $id = $this->insert($uid);
        } else {
            $success = $this->update($uid, $id);
        }

        if ($id === null || !$success) {
            return null;
        }

        return $id;
    }

    private function insert(string $uid): ?int
    {
        $query = 'INSERT INTO ' . $this->tokens_table . ' (' . self::UID_COL . ', id) VALUES (:userid, :id)';
        $i = 0;
        $params = [
            'userid' => $uid,
        ];
        do {
            $new_id = random_int(1, PHP_INT_MAX);
            $params['id'] = $new_id;
            $success = $this->db->write($query, $params);
        } while (!$success && $i++ < 3);

        return $success ? $new_id : null;
    }

    private function update(string $uid, int $id): bool
    {
        $params = [
            'userid' => $uid,
            'id' => $id,
        ];
        $query = 'UPDATE ' . $this->tokens_table . ' SET counter=counter+1'
            . ' WHERE ' . self::UID_COL . '=:userid AND id=:id';

        return (bool) $this->db->write($query, $params);
    }

    private function getSecurityAttributeOfUser(string $uid, string $query)
    {
        $statement = $this->db->read($query, [
            'userid' => $uid,
        ]);

        $attribute = $statement->fetchColumn();
        if ($attribute === false) {
            return null;
        }

        return $attribute;
    }
}
