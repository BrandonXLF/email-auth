<?php
/**
 * An exception for a missing DNS record.
 *
 * @package Email Auth
 * @subpackage DNS Tag-Value
 */

namespace EmailAuthPlugin\DNSTagValue;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once __DIR__ . '/class-exception.php';

/**
 * An exception for a missing DNS record.
 */
class MissingException extends Exception { }
