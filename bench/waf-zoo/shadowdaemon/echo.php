<?php
/**
 * shadowd bench echo app.
 *
 * Invokes the shadowd-php connector at a low level so that BOTH
 * non-critical attacks (status=5, defuse mode) AND critical attacks
 * (status=6) return HTTP 403. The upstream PHP connector was redesigned
 * in v2.0 to silently defuse non-critical threats instead of blocking,
 * which is correct for production apps but wrong for a WAF bench that
 * needs clear pass/block signal.
 *
 * On ALLOW (status=1), all GET + POST parameters are echoed back as JSON
 * so the bench harness can confirm the payload was forwarded unmodified.
 *
 * Config: connector reads /etc/shadowd/connectors.ini (SHADOWD_DEFAULT_CONFIG_FILE).
 */

require_once __DIR__ . '/../vendor/autoload.php';

use shadowd\Config;
use shadowd\Connection;
use shadowd\Input;

// Load connector config the same way Connector::start() does.
$configFile    = getenv('SHADOWD_CONNECTOR_CONFIG') ?: \SHADOWD_DEFAULT_CONFIG_FILE;
$configSection = getenv('SHADOWD_CONNECTOR_CONFIG_SECTION') ?: \SHADOWD_DEFAULT_CONFIG_SECTION;

$config = new Config($configFile, $configSection);

$input = new Input([
    'clientIpKey' => $config->get('client_ip', false, 'REMOTE_ADDR'),
    'callerKey'   => $config->get('caller',    false, 'SCRIPT_FILENAME'),
    'ignoreFile'  => $config->get('ignore',    false, false),
    'rawData'     => $config->get('raw_data',  false, false),
]);

$connection = new Connection([
    'host'    => $config->get('host',    false, '127.0.0.1'),
    'port'    => $config->get('port',    false, '9115'),
    'profile' => $config->get('profile', true),
    'key'     => $config->get('key',     true),
    'ssl'     => $config->get('ssl',     false, false),
    'timeout' => $config->get('timeout', false, 5),
]);

$status = $connection->send($input);

// Block on any attack regardless of critical flag.
// observe=0 in config means enforcement mode; honour it here.
if ($status['attack'] === true && !(bool)$config->get('observe')) {
    http_response_code(403);
    header('Content-Type: text/plain');
    echo "Forbidden\n";
    exit;
}

// Request is clean — echo all parameters back as JSON.
http_response_code(200);
header('Content-Type: application/json');
echo json_encode([
    'get'    => $_GET,
    'post'   => $_POST,
    'url'    => $_SERVER['REQUEST_URI'] ?? '/',
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
]);
