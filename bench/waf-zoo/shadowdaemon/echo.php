<?php
/**
 * shadowd bench echo app.
 *
 * Initialises the shadowd-php connector (which sends all request parameters
 * to the shadowd daemon for scoring). If shadowd returns BLOCK, the connector
 * exits with a 403 before we get here.
 *
 * On ALLOW, we echo all GET + POST parameters back as JSON so the bench
 * harness can confirm the payload was forwarded unmodified.
 *
 * Namespace: the library uses lowercase `shadowd` (not `Shadowd`).
 * Class:     `shadowd\Connector` (not `shadowd\Connector\Connector`).
 * Config:    the connector reads SHADOWD_CONNECTOR_CONFIG env var for the ini path.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use shadowd\Connector;

$connector = new Connector();
$connector->start();

// If we reach here, shadowd allowed the request.
http_response_code(200);
header('Content-Type: application/json');
echo json_encode([
    'get'    => $_GET,
    'post'   => $_POST,
    'url'    => $_SERVER['REQUEST_URI'] ?? '/',
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
]);
