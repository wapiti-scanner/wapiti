<?php

namespace WPForms\Emails;

use WPForms\Emails\Templates\General;

/**
 * Mailer class to wrap wp_mail().
 *
 * @since 1.5.4
 */
class Mailer {

	/**
	 * Array or comma-separated list of email addresses to send message.
	 *
	 * @since 1.5.4
	 *
	 * @var string|string[]
	 */
	private $to_email;

	/**
	 * CC addresses (comma delimited).
	 *
	 * @since 1.5.4
	 *
	 * @var string
	 */
	private $cc;

	/**
	 * From address.
	 *
	 * @since 1.5.4
	 *
	 * @var string
	 */
	private $from_address;

	/**
	 * From name.
	 *
	 * @since 1.5.4
	 *
	 * @var string
	 */
	private $from_name;

	/**
	 * Reply to address.
	 *
	 * @since 1.5.4
	 *
	 * @var string
	 */
	private $reply_to;

	/**
	 * Email headers.
	 *
	 * @since 1.5.4
	 *
	 * @var string
	 */
	private $headers;

	/**
	 * Email content type.
	 *
	 * @since 1.5.4
	 *
	 * @var string
	 */
	private $content_type;

	/**
	 * Email attachments.
	 *
	 * @since 1.5.4
	 *
	 * @var string
	 */
	private $attachments;

	/**
	 * Email subject.
	 *
	 * @since 1.5.4
	 *
	 * @var string
	 */
	private $subject;

	/**
	 * Email message.
	 *
	 * @since 1.5.4
	 *
	 * @var string
	 */
	private $message;

	/**
	 * Email template.
	 *
	 * @since 1.5.4
	 *
	 * @var General
	 */
	private $template;

	/**
	 * Set a property.
	 *
	 * @since 1.5.4
	 *
	 * @param string $key   Property name.
	 * @param string $value Property value.
	 */
	public function __set( $key, $value ) {

		$this->$key = $value;
	}

	/**
	 * Get a property.
	 *
	 * @since 1.5.4
	 *
	 * @param string $key Property name.
	 *
	 * @return string
	 */
	public function __get( $key ) {

		return $this->$key;
	}

	/**
	 * Check if a property exists.
	 *
	 * @since 1.5.4
	 *
	 * @param string $key Property name.
	 *
	 * @return bool
	 */
	public function __isset( $key ) {

		return isset( $this->key );
	}

	/**
	 * Unset a property.
	 *
	 * @since 1.5.4
	 *
	 * @param string $key Property name.
	 */
	public function __unset( $key ) {

		unset( $this->key );
	}

	/**
	 * Email kill switch if needed.
	 *
	 * @since 1.5.4
	 *
	 * @return bool
	 */
	public function is_email_disabled() {

		return (bool) \apply_filters( 'wpforms_emails_mailer_is_email_disabled', false, $this );
	}

	/**
	 * Sanitize the string.
	 *
	 * @uses \wpforms_decode_string()
	 *
	 * @since 1.5.4
	 * @since 1.6.0 Deprecated param: $linebreaks. This is handled by wpforms_decode_string().
	 *
	 * @param string $string String that may contain tags.
	 *
	 * @return string
	 */
	public function sanitize( $string = '' ) {

		return \wpforms_decode_string( $string );
	}

	/**
	 * Get the email from name.
	 *
	 * @since 1.5.4
	 *
	 * @return string
	 */
	public function get_from_name() {

		$this->from_name = $this->from_name ? $this->sanitize( $this->from_name ) : \get_bloginfo( 'name' );

		return \apply_filters( 'wpforms_emails_mailer_get_from_name', $this->from_name, $this );
	}

	/**
	 * Get the email from address.
	 *
	 * @since 1.5.4
	 *
	 * @return string
	 */
	public function get_from_address() {

		$this->from_address = $this->from_address ? $this->sanitize( $this->from_address ) : \get_option( 'admin_email' );

		return \apply_filters( 'wpforms_emails_mailer_get_from_address', $this->from_address, $this );
	}

	/**
	 * Get the email reply to address.
	 *
	 * @since 1.5.4
	 *
	 * @return string
	 */
	public function get_reply_to_address() {

		if ( empty( $this->reply_to ) || ! \is_email( $this->reply_to ) ) {
			$this->reply_to = $this->from_address;
		}

		$this->reply_to = $this->sanitize( $this->reply_to );

		if ( empty( $this->reply_to ) || ! \is_email( $this->reply_to ) ) {
			$this->reply_to = \get_option( 'admin_email' );
		}

		return \apply_filters( 'wpforms_emails_mailer_get_reply_to_address', $this->reply_to, $this );
	}

	/**
	 * Get the email carbon copy addresses.
	 *
	 * @since 1.5.4
	 *
	 * @return string The email carbon copy addresses.
	 */
	public function get_cc_address() {

		if ( empty( $this->cc ) ) {
			return \apply_filters( 'wpforms_emails_mailer_get_cc_address', $this->cc, $this );
		}

		$this->cc = $this->sanitize( $this->cc );

		$addresses = \array_map( 'trim', \explode( ',', $this->cc ) );

		foreach ( $addresses as $key => $address ) {
			if ( ! \is_email( $address ) ) {
				unset( $addresses[ $key ] );
			}
		}

		$this->cc = \implode( ',', $addresses );

		return \apply_filters( 'wpforms_emails_mailer_get_cc_address', $this->cc, $this );
	}

	/**
	 * Get the email content type.
	 *
	 * @since 1.5.4
	 *
	 * @return string The email content type.
	 */
	public function get_content_type() {

		$is_html = 'default' === \wpforms_setting( 'email-template', 'default' );

		if ( ! $this->content_type && $is_html ) {
			$this->content_type = \apply_filters( 'wpforms_emails_mailer_get_content_type_default', 'text/html', $this );
		} elseif ( ! $is_html ) {
			$this->content_type = 'text/plain';
		}

		return \apply_filters( 'wpforms_emails_mailer_get_content_type', $this->content_type, $this );
	}

	/**
	 * Get the email message.
	 *
	 * @since 1.5.4
	 *
	 * @return string The email message.
	 */
	public function get_message() {

		if ( empty( $this->message ) && ! empty( $this->template ) ) {
			$this->message = $this->template->get();
		}

		return \apply_filters( 'wpforms_emails_mailer_get_message', $this->message, $this );
	}

	/**
	 * Get the email headers.
	 *
	 * @since 1.5.4
	 *
	 * @return string The email headers.
	 */
	public function get_headers() {

		if ( $this->headers ) {
			return \apply_filters( 'wpforms_emails_mailer_get_headers', $this->headers, $this );
		}

		$this->headers = "From: {$this->get_from_name()} <{$this->get_from_address()}>\r\n";

		if ( $this->get_reply_to_address() ) {
			$this->headers .= "Reply-To: {$this->get_reply_to_address()}\r\n";
		}

		if ( $this->get_cc_address() ) {
			$this->headers .= "Cc: {$this->get_cc_address()}\r\n";
		}

		$this->headers .= "Content-Type: {$this->get_content_type()}; charset=utf-8\r\n";

		return \apply_filters( 'wpforms_emails_mailer_get_headers', $this->headers, $this );
	}

	/**
	 * Get the email attachments.
	 *
	 * @since 1.5.4
	 *
	 * @return string
	 */
	public function get_attachments() {

		return \apply_filters( 'wpforms_emails_mailer_get_attachments', $this->attachments, $this );
	}

	/**
	 * Set email address to send to.
	 *
	 * @since 1.5.4
	 *
	 * @param string|string[] $email Array or comma-separated list of email addresses to send message.
	 *
	 * @return Mailer
	 */
	public function to_email( $email ) {

		if ( is_string( $email ) ) {
			$email = explode( ',', $email );
		}

		$this->to_email = \apply_filters( 'wpforms_emails_mailer_to_email', $email, $this );

		return $this;
	}

	/**
	 * Set email subject.
	 *
	 * @since 1.5.4
	 *
	 * @param string $subject Email subject.
	 *
	 * @return Mailer
	 */
	public function subject( $subject ) {

		$subject = $this->sanitize( $subject );

		$this->subject = \apply_filters( 'wpforms_emails_mailer_subject', $subject, $this );

		return $this;
	}

	/**
	 * Set email message (body).
	 *
	 * @since 1.5.4
	 *
	 * @param string $message Email message.
	 *
	 * @return Mailer
	 */
	public function message( $message ) {

		$this->message = \apply_filters( 'wpforms_emails_mailer_message', $message, $this );

		return $this;
	}

	/**
	 * Set email template.
	 *
	 * @since 1.5.4
	 *
	 * @param General $template Email template.
	 *
	 * @return Mailer
	 */
	public function template( General $template ) {

		$this->template = \apply_filters( 'wpforms_emails_mailer_template', $template, $this );

		return $this;
	}

	/**
	 * Get email errors.
	 *
	 * @since 1.5.4
	 *
	 * @return array
	 */
	protected function get_errors() {

		$errors = [];

		foreach ( (array) $this->to_email as $email ) {
			if ( ! is_email( $email ) ) {
				$errors[] = sprintf( /* translators: %1$s - namespaced class name, %2$s - invalid email. */
					esc_html__( '%1$s Invalid email address %2$s.', 'wpforms-lite' ),
					'[WPForms\Emails\Mailer]',
					$email
				);
			}
		}

		if ( empty( $this->subject ) ) {
			$errors[] = sprintf( /* translators: %s - namespaced class name. */
				esc_html__( '%s Empty subject line.', 'wpforms-lite' ),
				'[WPForms\Emails\Mailer]'
			);
		}

		if ( empty( $this->get_message() ) ) {
			$errors[] = sprintf( /* translators: %s - namespaced class name. */
				esc_html__( '%s Empty message.', 'wpforms-lite' ),
				'[WPForms\Emails\Mailer]'
			);
		}

		return $errors;
	}

	/**
	 * Log given email errors.
	 *
	 * @since 1.5.4
	 *
	 * @param array $errors Errors to log.
	 */
	protected function log_errors( $errors ) {

		if ( empty( $errors ) || ! \is_array( $errors ) ) {
			return;
		}

		foreach ( $errors as $error ) {
			\wpforms_log(
				$error,
				[
					'to_email' => $this->to_email,
					'subject'  => $this->subject,
					'message'  => \wp_trim_words( $this->get_message() ),
				],
				[
					'type' => 'error',
				]
			);
		}
	}

	/**
	 * Send the email.
	 *
	 * @since 1.5.4
	 *
	 * @return bool
	 */
	public function send() {

		if ( ! \did_action( 'init' ) && ! \did_action( 'admin_init' ) ) {
			\_doing_it_wrong( __FUNCTION__, \esc_html__( 'You cannot send emails with WPForms\Emails\Mailer until init/admin_init has been reached.', 'wpforms-lite' ), null );

			return false;
		}

		// Don't send anything if emails have been disabled.
		if ( $this->is_email_disabled() ) {
			return false;
		}

		$errors = $this->get_errors();

		if ( $errors ) {
			$this->log_errors( $errors );
			return false;
		}

		$this->send_before();

		$sent = \wp_mail(
			$this->to_email,
			$this->subject,
			$this->get_message(),
			$this->get_headers(),
			$this->get_attachments()
		);

		$this->send_after();

		return $sent;
	}

	/**
	 * Add filters / actions before the email is sent.
	 *
	 * @since 1.5.4
	 */
	public function send_before() {

		do_action( 'wpforms_emails_mailer_send_before', $this );
		add_filter( 'wp_mail_from', [ $this, 'get_from_address' ] );
		add_filter( 'wp_mail_from_name', [ $this, 'get_from_name' ] );
		add_filter( 'wp_mail_content_type', [ $this, 'get_content_type' ] );
	}

	/**
	 * Remove filters / actions after the email is sent.
	 *
	 * @since 1.5.4
	 */
	public function send_after() {

		do_action( 'wpforms_emails_mailer_send_after', $this );
		remove_filter( 'wp_mail_from', [ $this, 'get_from_address' ] );
		remove_filter( 'wp_mail_from_name', [ $this, 'get_from_name' ] );
		remove_filter( 'wp_mail_content_type', [ $this, 'get_content_type' ] );
	}
}
