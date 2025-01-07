<?php
/**
 * An exception for a missing DNS record.
 *
 * @package Email Auth
 * @subpackage DNS Tag-Value
 */

namespace EmailAuthPlugin\DNSTagValue;

require __DIR__ . '/class-exception.php';

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * An exception for a missing DNS record.
 */
class MissingException extends Exception { }
