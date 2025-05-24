<?php
/**
 * An exception for an invalid DNS state.
 *
 * @package Email Auth
 * @subpackage DNS Tag-Value
 */

namespace EmailAuthPlugin\DNSTagValue;

require_once __DIR__ . '/class-exception.php';

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * An exception for an invalid DNS state.
 */
class InvalidException extends Exception { }
