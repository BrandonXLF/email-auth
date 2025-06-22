<?php
/**
 * An exception for a malformed DNS record.
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
 * An exception for a malformed DNS record.
 */
class MalformedException extends Exception {
	/**
	 * The record text that caused the exception.
	 *
	 * @var string
	 */
	protected $record_text;

	/**
	 * Constructor.
	 *
	 * @param string $message The exception message.
	 * @param string $record_text The text of the record that caused the exception.
	 */
	public function __construct( $message, $record_text ) {
		parent::__construct( $message );
		$this->record_text = $record_text;
	}

	/**
	 * Get the record text that caused the exception.
	 *
	 * @return string The record text.
	 */
	public function getRecordText() {
		return $this->record_text;
	}
}
