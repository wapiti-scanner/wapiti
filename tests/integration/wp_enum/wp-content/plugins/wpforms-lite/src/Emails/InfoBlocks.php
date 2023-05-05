<?php
namespace WPForms\Emails;

/**
 * Fetching and formatting Info Blocks for Email Summaries class.
 *
 * @since 1.5.4
 */
class InfoBlocks {

	/**
	 * Source of info blocks content.
	 *
	 * @since 1.5.4
	 */
	const SOURCE_URL = 'https://wpforms.com/wp-content/email-summaries.json';

	/**
	 * Get info blocks info from the cache file or remote.
	 *
	 * @since 1.6.4
	 *
	 * @return array
	 */
	public function get_all() {

		$cache_file = $this->get_cache_file_path();

		if ( empty( $cache_file ) || ! is_readable( $cache_file ) ) {
			return $this->fetch_all();
		}

		$contents = file_get_contents( $cache_file );
		$contents = json_decode( $contents, true );

		return $this->verify_fetched( $contents );
	}

	/**
	 * Fetch info blocks info from remote.
	 *
	 * @since 1.5.4
	 *
	 * @return array
	 */
	public function fetch_all() {

		$info = [];

		$res = wp_remote_get(
			self::SOURCE_URL,
			[
				'timeout'    => 10,
				'user-agent' => wpforms_get_default_user_agent(),
			]
		);

		if ( is_wp_error( $res ) ) {
			return $info;
		}

		$body = wp_remote_retrieve_body( $res );

		if ( empty( $body ) ) {
			return $info;
		}

		$body = json_decode( $body, true );

		return $this->verify_fetched( $body );
	}

	/**
	 * Verify fetched blocks data.
	 *
	 * @since 1.5.4
	 *
	 * @param array $fetched Fetched blocks data.
	 *
	 * @return array
	 */
	protected function verify_fetched( $fetched ) {

		$info = [];

		if ( ! \is_array( $fetched ) ) {
			return $info;
		}

		foreach ( $fetched as $item ) {

			if ( empty( $item['id'] ) ) {
				continue;
			}

			$id = \absint( $item['id'] );

			if ( empty( $id ) ) {
				continue;
			}

			$info[ $id ] = $item;
		}

		return $info;
	}

	/**
	 * Get info blocks relevant to customer's licence.
	 *
	 * @since 1.5.4
	 *
	 * @return array
	 */
	protected function get_by_license() {

		$data     = $this->get_all();
		$filtered = [];

		if ( empty( $data ) || ! \is_array( $data ) ) {
			return $filtered;
		}

		$license_type = \wpforms_setting( 'type', false, 'wpforms_license' );

		foreach ( $data as $key => $item ) {

			if ( ! isset( $item['type'] ) || ! \is_array( $item['type'] ) ) {
				continue;
			}

			if ( ! \in_array( $license_type, $item['type'], true ) ) {
				continue;
			}

			$filtered[ $key ] = $item;
		}

		return $filtered;
	}

	/**
	 * Get the first block with a valid id.
	 * Needed to ignore blocks with invalid/missing ids.
	 *
	 * @since 1.5.4
	 *
	 * @param array $data Blocks array.
	 *
	 * @return array
	 */
	protected function get_first_with_id( $data ) {

		if ( empty( $data ) || ! \is_array( $data ) ) {
			return [];
		}

		foreach ( $data as $item ) {
			$item_id = \absint( $item['id'] );
			if ( ! empty( $item_id ) ) {
				return $item;
			}
		}

		return [];
	}

	/**
	 * Get next info block that wasn't sent yet.
	 *
	 * @since 1.5.4
	 *
	 * @return array
	 */
	public function get_next() {

		$data  = $this->get_by_license();
		$block = [];

		if ( empty( $data ) || ! \is_array( $data ) ) {
			return $block;
		}

		$blocks_sent = \get_option( 'wpforms_emails_infoblocks_sent' );

		if ( empty( $blocks_sent ) || ! \is_array( $blocks_sent ) ) {
			$block = $this->get_first_with_id( $data );
		}

		if ( empty( $block ) ) {
			$data  = \array_diff_key( $data, \array_flip( $blocks_sent ) );
			$block = $this->get_first_with_id( $data );
		}

		return $block;
	}

	/**
	 * Register a block as sent.
	 *
	 * @since 1.5.4
	 *
	 * @param array $info_block Info block.
	 */
	public function register_sent( $info_block ) {

		$block_id = isset( $info_block['id'] ) ? absint( $info_block['id'] ) : false;

		if ( empty( $block_id ) ) {
			return;
		}

		$option_name = 'wpforms_email_summaries_info_blocks_sent';
		$blocks      = get_option( $option_name );

		if ( empty( $blocks ) || ! is_array( $blocks ) ) {
			update_option( $option_name, [ $block_id ] );

			return;
		}

		if ( in_array( $block_id, $blocks, true ) ) {
			return;
		}

		$blocks[] = $block_id;

		update_option( $option_name, $blocks );
	}

	/**
	 * Get a path of the blocks cache file.
	 *
	 * @since 1.6.4
	 *
	 * @return string
	 */
	public function get_cache_file_path() {

		$upload_dir = wpforms_upload_dir();

		if ( ! isset( $upload_dir['path'] ) ) {
			return '';
		}

		$cache_dir = trailingslashit( $upload_dir['path'] ) . 'cache';

		return wp_normalize_path( trailingslashit( $cache_dir ) . 'email-summaries.json' );
	}

	/**
	 * Fetch and cache blocks in a file.
	 *
	 * @since 1.6.4
	 */
	public function cache_all() {

		$file_path = $this->get_cache_file_path();

		if ( empty( $file_path ) ) {
			return;
		}

		$dir = dirname( $file_path );

		if ( ! wp_mkdir_p( $dir ) ) {
			return;
		}

		wpforms_create_index_html_file( $dir );
		wpforms_create_upload_dir_htaccess_file();

		$info_blocks = $this->fetch_all();

		file_put_contents( $file_path, wp_json_encode( $info_blocks ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
	}
}
