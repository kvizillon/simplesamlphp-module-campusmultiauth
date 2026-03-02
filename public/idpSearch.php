<?php

declare(strict_types=1);

use SimpleSAML\Configuration;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module\campusmultiauth\Auth\Source\Campusidp;

header('Content-type: application/json');

$language = $_GET['language'] ?? 'en';

$metadataStorageHandler = MetaDataStorageHandler::getMetadataHandler();
$metadata = $metadataStorageHandler->getList();

if (!empty($_GET['idphint']) && !isset($_GET['index'])) {
    $filteredData = array_intersect_key($metadata, array_flip(json_decode($_GET['idphint'], true)));
} else {
    $index = $_GET['index'];
    $searchTerm = $_GET['q'] ?? '';
    $skipMatching = $_GET['skipMatching'] ?? false;

    $config = Configuration::getConfig('module_campusmultiauth.php')->toArray();
    $searchBox = $config['components'][$index];

    if (!empty($_GET['aarc_discovery_hint_uri'])) {
        $idphint = Campusidp::getHintedIdps([
            'aarc_discovery_hint_uri' => json_decode($_GET['aarc_discovery_hint_uri'])
        ]);
    } elseif (!empty($_GET['aarc_discovery_hint'])) {
        $idphint = Campusidp::getHintedIdps(['aarc_discovery_hint' => json_decode($_GET['aarc_discovery_hint'])]);
    } elseif (!empty($_GET['idphint'])) {
        $idphint = $_GET['idphint'];
        if (!is_array($idphint)) {
            $idphint = json_decode($idphint, true);
        }
    } else {
        $idphint = [];
    }

    $metadata = array_intersect_key($metadata, array_flip($idphint));

    if (array_key_exists('filter', $searchBox)) {
        $configFilteredIdps = Campusidp::getHintedIdps(['aarc_discovery_hint' => $searchBox['filter']]);

        $metadata = array_intersect_key($metadata, array_flip($configFilteredIdps));
    }

    if ($skipMatching) {
        $filteredData = $metadata;
    } else {
        $filteredData = Campusidp::getIdpsMatchedBySearchTerm($metadata, $searchTerm);
    }
}

$data['items'] = [];

foreach ($filteredData as $entityid => $idpentry) {
    $item['idpentityid'] = $entityid;
    $item['image'] = $searchBox['logos'][$entityid] ?? Campusidp::getMostSquareLikeImg($idpentry);

    if (!empty($idpentry['name'][$language])) {
        $item['text'] = $idpentry['name'][$language];
    } elseif (!empty($idpentry['name']['en'])) {
        $item['text'] = $idpentry['name']['en'];
    } elseif (reset($idpentry['name'])) {
        $item['text'] = reset($idpentry['name']);
    } else {
        $item['text'] = 'undefined';
    }

    $data['items'][] = $item;
}

echo json_encode($data);
