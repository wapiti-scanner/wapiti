<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Sitemaps are stored in the database using a custom table. This class
 * provides a small API for storing and retrieving sitemap data so we can
 * avoid lots of explicit SQL juggling while building sitemaps. This file
 * also includes the SQL used to retrieve posts and images to be included
 * in the sitemaps.
 *
 * @since 4.8.0
 * @package automattic/jetpack
 */

/* Ensure sitemap constants are available. */
require_once __DIR__ . '/sitemap-constants.php';

/**
 * This object handles any database interaction required
 * for sitemap generation.
 *
 * @since 4.8.0
 */
class Jetpack_Sitemap_Librarian {

	/**
	 * Retrieve a single sitemap with given name and type.
	 * Returns null if no such sitemap exists.
	 *
	 * @access public
	 * @since 4.8.0
	 *
	 * @param string $name Name of the sitemap to be retrieved.
	 * @param string $type Type of the sitemap to be retrieved.
	 *
	 * @return array $args {
	 *   @type int    $id        ID number of the sitemap in the database.
	 *   @type string $timestamp Most recent timestamp of the resources pointed to.
	 *   @type string $name      Name of the sitemap in the database.
	 *   @type string $type      Type of the sitemap in the database.
	 *   @type string $text      The content of the sitemap.
	 * }
	 */
	public function read_sitemap_data( $name, $type ) {
		$post_array = get_posts(
			array(
				'numberposts' => 1,
				'title'       => $name,
				'post_type'   => $type,
				'post_status' => 'draft',
			)
		);

		$the_post = array_shift( $post_array );

		if ( null === $the_post ) {
			return null;
		} else {
			return array(
				'id'        => $the_post->ID,
				'timestamp' => $the_post->post_date,
				'name'      => $the_post->post_title,
				'type'      => $the_post->post_type,
				'text'      => base64_decode( $the_post->post_content ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			);
		}
	}

	/**
	 * Store a sitemap of given type and index in the database.
	 * Note that the timestamp is reencoded as 'Y-m-d H:i:s'.
	 *
	 * If a sitemap with that type and name does not exist, create it.
	 * If a sitemap with that type and name does exist, update it.
	 *
	 * @access public
	 * @since 4.8.0
	 *
	 * @param string $index     Index of the sitemap to be stored.
	 * @param string $type      Type of the sitemap to be stored.
	 * @param string $contents  Contents of the sitemap to be stored.
	 * @param string $timestamp Timestamp of the sitemap to be stored, in 'YYYY-MM-DD hh:mm:ss' format.
	 */
	public function store_sitemap_data( $index, $type, $contents, $timestamp ) {
		$name = jp_sitemap_filename( $type, $index );

		$the_post = $this->read_sitemap_data( $name, $type );

		if ( null === $the_post ) {
			// Post does not exist.
			wp_insert_post(
				array(
					'post_title'   => $name,
					'post_content' => base64_encode( $contents ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
					'post_type'    => $type,
					'post_date'    => gmdate( 'Y-m-d H:i:s', strtotime( $timestamp ) ),
				)
			);
		} else {
			// Post does exist.
			wp_insert_post(
				array(
					'ID'           => $the_post['id'],
					'post_title'   => $name,
					'post_content' => base64_encode( $contents ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
					'post_type'    => $type,
					'post_date'    => gmdate( 'Y-m-d H:i:s', strtotime( $timestamp ) ),
				)
			);
		}
	}

	/**
	 * Delete a sitemap by name and type.
	 *
	 * @access public
	 * @since 4.8.0
	 *
	 * @param string $name Row name.
	 * @param string $type Row type.
	 *
	 * @return bool 'true' if a row was deleted, 'false' otherwise.
	 */
	public function delete_sitemap_data( $name, $type ) {
		$the_post = $this->read_sitemap_data( $name, $type );

		if ( null === $the_post ) {
			return false;
		} else {
			wp_delete_post( $the_post['id'] );
			return true;
		}
	}

	/**
	 * Retrieve the contents of a sitemap with given name and type.
	 * If no such sitemap exists, return the empty string. Note that the
	 * returned string is run through wp_specialchars_decode.
	 *
	 * @access public
	 * @since 4.8.0
	 *
	 * @param string $name Row name.
	 * @param string $type Row type.
	 *
	 * @return string Text of the specified sitemap, or the empty string.
	 */
	public function get_sitemap_text( $name, $type ) {
		$row = $this->read_sitemap_data( $name, $type );

		if ( null === $row ) {
			return '';
		} else {
			return $row['text'];
		}
	}

	/**
	 * Delete numbered sitemaps named prefix-(p+1), prefix-(p+2), ...
	 * until the first nonexistent sitemap is found.
	 *
	 * @access public
	 * @since 4.8.0
	 *
	 * @param int    $position Number before the first sitemap to be deleted.
	 * @param string $type Sitemap type.
	 */
	public function delete_numbered_sitemap_rows_after( $position, $type ) {
		$any_left = true;

		while ( true === $any_left ) {
			++$position;
			$name     = jp_sitemap_filename( $type, $position );
			$any_left = $this->delete_sitemap_data( $name, $type );
		}
	}

	/**
	 * Deletes all stored sitemap data.
	 *
	 * @access public
	 * @since 4.8.0
	 */
	public function delete_all_stored_sitemap_data() {
		$this->delete_sitemap_type_data( JP_MASTER_SITEMAP_TYPE );
		$this->delete_sitemap_type_data( JP_PAGE_SITEMAP_TYPE );
		$this->delete_sitemap_type_data( JP_PAGE_SITEMAP_INDEX_TYPE );
		$this->delete_sitemap_type_data( JP_IMAGE_SITEMAP_TYPE );
		$this->delete_sitemap_type_data( JP_IMAGE_SITEMAP_INDEX_TYPE );
		$this->delete_sitemap_type_data( JP_VIDEO_SITEMAP_TYPE );
		$this->delete_sitemap_type_data( JP_VIDEO_SITEMAP_INDEX_TYPE );
	}

	/**
	 * Deletes all sitemap data of specific type
	 *
	 * @access protected
	 * @since 5.3.0
	 *
	 * @param String $type Type of sitemap.
	 */
	protected function delete_sitemap_type_data( $type ) {
		$ids = get_posts(
			array(
				'post_type'   => $type,
				'post_status' => 'draft',
				'fields'      => 'ids',
			)
		);

		foreach ( $ids as $id ) {
			wp_trash_post( $id );
		}
	}

	/**
	 * Retrieve an array of sitemap rows (of a given type) sorted by ID.
	 *
	 * Returns the smallest $num_posts sitemap rows (measured by ID)
	 * of the given type which are larger than $from_id.
	 *
	 * @access public
	 * @since 4.8.0
	 *
	 * @param string $type Type of the sitemap rows to retrieve.
	 * @param int    $from_id Greatest lower bound of retrieved sitemap post IDs.
	 * @param int    $num_posts Largest number of sitemap posts to retrieve.
	 *
	 * @return array The sitemaps, as an array of associative arrays.
	 */
	public function query_sitemaps_after_id( $type, $from_id, $num_posts ) {
		global $wpdb;

		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT *
					FROM $wpdb->posts
					WHERE post_type=%s
						AND post_status=%s
						AND ID>%d
					ORDER BY ID ASC
					LIMIT %d;",
				$type,
				'draft',
				$from_id,
				$num_posts
			),
			ARRAY_A
		); // WPCS: db call ok; no-cache ok.
	}

	/**
	 * Retrieve an array of posts sorted by ID.
	 *
	 * More precisely, returns the smallest $num_posts posts
	 * (measured by ID) which are larger than $from_id.
	 *
	 * @access public
	 * @since 4.8.0
	 *
	 * @param int $from_id Greatest lower bound of retrieved post IDs.
	 * @param int $num_posts Largest number of posts to retrieve.
	 *
	 * @return array The posts.
	 */
	public function query_posts_after_id( $from_id, $num_posts ) {
		global $wpdb;

		// Get the list of post types to include and prepare for query.
		$post_types = Jetpack_Options::get_option_and_ensure_autoload(
			'jetpack_sitemap_post_types',
			array( 'page', 'post' )
		);
		foreach ( (array) $post_types as $i => $post_type ) {
			$post_types[ $i ] = $wpdb->prepare( '%s', $post_type );
		}
		$post_types_list = join( ',', $post_types );

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- WPCS: db call ok; no-cache ok.
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT *
					FROM $wpdb->posts
					WHERE post_status='publish'
						AND post_type IN ($post_types_list)
						AND ID>%d
					ORDER BY ID ASC
					LIMIT %d;",
				$from_id,
				$num_posts
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	/**
	 * Get the most recent timestamp among approved comments for the given post_id.
	 *
	 * @access public
	 * @since 4.8.0
	 *
	 * @param int $post_id Post identifier.
	 *
	 * @return int Timestamp in 'Y-m-d h:i:s' format (UTC) of the most recent comment on the given post, or null if no such comments exist.
	 */
	public function query_latest_approved_comment_time_on_post( $post_id ) {
		global $wpdb;

		return $wpdb->get_var(
			$wpdb->prepare(
				"SELECT MAX(comment_date_gmt)
					FROM $wpdb->comments
					WHERE comment_post_ID = %d AND comment_approved = '1' AND comment_type in ( '', 'comment' )",
				$post_id
			)
		);
	}

	/**
	 * Retrieve an array of image posts sorted by ID.
	 *
	 * More precisely, returns the smallest $num_posts image posts
	 * (measured by ID) which are larger than $from_id.
	 *
	 * @access public
	 * @since 4.8.0
	 *
	 * @param int $from_id Greatest lower bound of retrieved image post IDs.
	 * @param int $num_posts Largest number of image posts to retrieve.
	 *
	 * @return array The posts.
	 */
	public function query_images_after_id( $from_id, $num_posts ) {
		global $wpdb;

		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT *
					FROM $wpdb->posts
					WHERE post_type='attachment'
						AND post_mime_type LIKE %s
						AND ID>%d
					ORDER BY ID ASC
					LIMIT %d;",
				'image/%',
				$from_id,
				$num_posts
			)
		); // WPCS: db call ok; no-cache ok.
	}

	/**
	 * Retrieve an array of video posts sorted by ID.
	 *
	 * More precisely, returns the smallest $num_posts video posts
	 * (measured by ID) which are larger than $from_id.
	 *
	 * @access public
	 * @since 4.8.0
	 *
	 * @param int $from_id Greatest lower bound of retrieved video post IDs.
	 * @param int $num_posts Largest number of video posts to retrieve.
	 *
	 * @return array The posts.
	 */
	public function query_videos_after_id( $from_id, $num_posts ) {
		global $wpdb;

		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT *
					FROM $wpdb->posts
					WHERE post_type='attachment'
						AND post_mime_type LIKE %s
						AND ID>%d
					ORDER BY ID ASC
					LIMIT %d;",
				'video/%',
				$from_id,
				$num_posts
			)
		); // WPCS: db call ok; no-cache ok.
	}

	/**
	 * Retrieve an array of published posts from the last 2 days.
	 *
	 * @access public
	 * @since 4.8.0
	 *
	 * @param int $num_posts Largest number of posts to retrieve.
	 *
	 * @return array The posts.
	 */
	public function query_most_recent_posts( $num_posts ) {
		global $wpdb;

		$two_days_ago = gmdate( 'Y-m-d', strtotime( '-2 days' ) );

		/**
		 * Filter post types to be included in news sitemap.
		 *
		 * @module sitemaps
		 *
		 * @since 3.9.0
		 *
		 * @param array $post_types Array with post types to include in news sitemap.
		 */
		$post_types = apply_filters(
			'jetpack_sitemap_news_sitemap_post_types',
			array( 'page', 'post' )
		);

		foreach ( (array) $post_types as $i => $post_type ) {
			$post_types[ $i ] = $wpdb->prepare( '%s', $post_type );
		}

		$post_types_list = join( ',', $post_types );

		// phpcs:disable WordPress.DB.PreparedSQLPlaceholders.QuotedSimplePlaceholder,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- WPCS: db call ok; no-cache ok.
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT *
					FROM $wpdb->posts
					WHERE post_status='publish'
						AND post_date >= '%s'
						AND post_type IN ($post_types_list)
					ORDER BY post_date DESC
					LIMIT %d;",
				$two_days_ago,
				$num_posts
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQLPlaceholders.QuotedSimplePlaceholder,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

}
