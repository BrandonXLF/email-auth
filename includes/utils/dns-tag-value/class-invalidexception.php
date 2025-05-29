<?php
/**
 * An exception for an invalid DNS state.
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
 * An exception for an invalid DNS state.
 */
class InvalidException extends Exception { }
