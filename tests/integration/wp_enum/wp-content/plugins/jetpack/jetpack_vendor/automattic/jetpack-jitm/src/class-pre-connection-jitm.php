<?php
/**
 * Jetpack's Pre-Connection JITM class.
 *
 * @package automattic/jetpack-jitm
 */

namespace Automattic\Jetpack\JITMS;

/**
 * Jetpack pre-connection just in time messaging through out the admin.
 */
class Pre_Connection_JITM extends JITM {

	/**
	 * Filters and formats the messages for the client-side JS renderer
	 *
	 * @param string $message_path Current message path.
	 *
	 * @return array Formatted messages.
	 */
	private function filter_messages( $message_path ) {
		/**
		 * Allows filtering of the pre-connection JITMs.
		 *
		 * This filter allows plugins to add pre-connection JITMs that will be
		 * displayed by the JITM package.
		 *
		 * @since 1.14.1
		 *
		 * @param array An array of pre-connection messages.
		 */
		$messages = apply_filters( 'jetpack_pre_connection_jitms', array() );

		$messages = $this->validate_messages( $messages );

		$formatted_messages = array();

		foreach ( $messages as $message ) {
			if ( ! preg_match( $message['message_path'], $message_path ) ) {
				continue;
			}

			$obj                 = new \stdClass();
			$obj->CTA            = array( // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
				'message'   => $message['button_caption'],
				'newWindow' => false,
			);
			$obj->url            = $message['button_link'];
			$obj->id             = $message['id'];
			$obj->is_dismissible = true;
			$obj->content        = array(
				'message'     => $message['message'],
				'description' => $message['description'],
				'list'        => array(),
				'icon'        => $this->get_message_icon( $message ),
			);

			$formatted_messages[] = $obj;
		}

		return $formatted_messages;
	}

	/**
	 * Validates that each of the messages contains all of the required keys:
	 *   - id
	 *   - message_path
	 *   - message
	 *   - description
	 *   - button_link
	 *   - button_caption
	 *
	 * @param array $messages An array of JITM messages.
	 *
	 * @return array An array of JITM messages that contain all of the required keys.
	 */
	private function validate_messages( $messages ) {
		if ( ! is_array( $messages ) ) {
			return array();
		}

		$expected_keys = array_flip( array( 'id', 'message_path', 'message', 'description', 'button_link', 'button_caption' ) );

		foreach ( $messages as $index => $message ) {
			if ( count( array_intersect_key( $expected_keys, $message ) ) !== count( $expected_keys ) ) {
				// Remove any messages that are missing expected keys.
				unset( $messages[ $index ] );
			}
		}

		return $messages;
	}

	/**
	 * Get the icon for the message.
	 *
	 * The message may contain an 'icon' key. If the value of the 'icon' key matches a supported icon (or empty string), the value is used.
	 * If the message does not contain an icon key or if the value does not match a supported icon, the Jetpack icon is used by default.
	 *
	 * @param array $message A pre-connection JITM.
	 *
	 * @return string The icon to use in the JITM.
	 */
	private function get_message_icon( $message ) {
		// Default to the Jetpack icon.
		$icon = 'jetpack';

		if ( ! isset( $message['icon'] ) ) {
			return $icon;
		}

		$supported_icons = $this->get_supported_icons();

		if ( in_array( $message['icon'], $supported_icons, true ) ) {
			// Only use the message icon if it's a supported icon or an empty string (for no icon).
			$icon = $message['icon'];
		}

		return $icon;
	}

	/**
	 * Retrieve the current message to display keyed on query string and message path
	 *
	 * @param string $message_path The message path to ask for.
	 * @param string $query The query string originally from the front end. Unused in this subclass.
	 * @param bool   $full_jp_logo_exists If there is a full Jetpack logo already on the page.
	 *
	 * @return array The JITMs to show, or an empty array if there is nothing to show
	 */
	public function get_messages( $message_path, $query, $full_jp_logo_exists ) {
		if ( ! current_user_can( 'install_plugins' ) ) {
			return array();
		}

		$messages = $this->filter_messages( $message_path );

		if ( empty( $messages ) ) {
			return array();
		}

		$hidden_jitms = \Jetpack_Options::get_option( 'hide_jitm' );

		foreach ( $messages as $idx => &$envelope ) {
			$dismissed_feature = isset( $hidden_jitms[ 'pre-connection-' . $envelope->id ] ) &&
				is_array( $hidden_jitms[ 'pre-connection-' . $envelope->id ] ) ? $hidden_jitms[ 'pre-connection-' . $envelope->id ] : null;

			if ( is_array( $dismissed_feature ) ) {
				unset( $messages[ $idx ] );
				continue;
			}

			$envelope->content['icon'] = $this->generate_icon( $envelope->content['icon'], $full_jp_logo_exists );
		}

		return $messages;
	}

	/**
	 * Dismisses a JITM ID so that it will no longer be shown.
	 *
	 * @param string $id The id of the JITM that was dismissed.
	 *
	 * @return bool Always true
	 */
	public function dismiss( $id ) {
		$this->save_dismiss( 'pre-connection-' . $id );
		return true;
	}
}
