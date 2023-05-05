<?php
namespace W3TC;

class Util_PageUrls {
	/**
	 * Returns full urls for frontpage including older pages
	 *
	 * @param int     $limit_post_pages default is 10
	 * @return array
	 */
	static public function get_frontpage_urls( $limit_post_pages = 10 ) {
		static $frontpage_urls = array();

		if ( !isset( $frontpage_urls[$limit_post_pages] ) ) {
			$front_page = get_option( 'show_on_front' );
			$full_urls = array();
			$home_path = Util_Environment::home_url_uri();
			$site_path = Util_Environment::site_url_uri();

			$full_urls[] = get_home_url() . '/';

			if ( $site_path != $home_path ) {
				$full_urls[] = site_url() . '/';
			}

			$full_urls  = array_merge( $full_urls,
				self::get_older_pages( $home_path, $limit_post_pages, 'post' ) );
			$frontpage_urls[$limit_post_pages] = $full_urls;
		}
		return $frontpage_urls[$limit_post_pages];
	}

	/**
	 * Return full urls for the page with posts including older pages
	 *
	 * @param int     $limit_post_pages default is 10
	 * @return array
	 */
	static public function get_postpage_urls( $limit_post_pages = 10 ) {
		static $postpage_urls = array();

		if ( !isset( $postpage_urls[$limit_post_pages] ) ) {
			$posts_page_uri = '';
			$full_urls = array();

			$posts_page_id = get_option( 'page_for_posts' );
			if ( $posts_page_id ) {
				$posts_page_uri = get_page_uri( $posts_page_id );
				$page_link = get_home_url() . '/' . trim( $posts_page_uri, '/' ) . '/';
				$full_urls[] = $page_link;
			}
			if ( $posts_page_uri )
				$full_urls = array_merge( $full_urls, self::get_older_pages( $posts_page_uri, $limit_post_pages, 'post' ) );
			$postpage_urls[$limit_post_pages] = $full_urls;
		}

		return $postpage_urls[$limit_post_pages];
	}

	/**
	 * Returns all urls related to a custom post type post
	 *
	 * @since 2.1.7
	 *
	 * @param unknown $post_id
	 * @param int     $limit_post_pages default is 10
	 * @return array
	 */
	static public function get_cpt_archive_urls( $post_id, $limit_post_pages = 10 ) {
		static $cpt_archive_urls = array();
		$post = get_post( $post_id );

		if( $post && Util_Environment::is_custom_post_type( $post ) && !isset( $cpt_archive_urls[$limit_post_pages] ) ) {
			$full_urls = array();
			$post_type = $post->post_type;
			$archive_link = get_post_type_archive_link($post_type);
			$posts_page_uri = str_replace( home_url(), '', $archive_link );

			if ( $posts_page_uri ) {
				$full_urls[] = $archive_link;
				$full_urls = array_merge( $full_urls, self::get_older_pages( $posts_page_uri, $limit_post_pages, $post_type ) );
			}

			$cpt_archive_urls[$limit_post_pages] = $full_urls;
		}

		return $cpt_archive_urls[$limit_post_pages];
	}

	/**
	 * Return older pages listing posts
	 *
	 * @param unknown $posts_page_uri
	 * @param int     $limit_post_pages default is 10
	 * @param string  $post_type default is post
	 * @return array
	 */
	static private function get_older_pages( $posts_page_uri, $limit_post_pages = 10, $post_type = 'post' ) {
		$full_urls = array();
		$count_posts = wp_count_posts($post_type);
		$posts_number = $count_posts->publish;
		$posts_per_page = get_option( 'posts_per_page' );
		$posts_pages_number = @ceil( $posts_number / $posts_per_page );

		if ( $limit_post_pages > 0 && $posts_pages_number > $limit_post_pages ) {
			$posts_pages_number = $limit_post_pages;
		}

		for ( $pagenum = 2; $pagenum <= $posts_pages_number; $pagenum++ ) {
			$home_pagenum_link = self::get_pagenum_link( $posts_page_uri, $pagenum );
			$full_urls[] = $home_pagenum_link;
		}
		return $full_urls;
	}

	/**
	 * Returns all urls related to a post
	 *
	 * @param unknown $post_id
	 * @return array
	 */
	static public function get_post_urls( $post_id ) {
		static $post_urls = array();

		if ( !isset( $post_urls[$post_id] ) ) {
			$full_urls = array();
			$post_link = get_permalink( $post_id );
			$post_uri = str_replace( Util_Environment::home_domain_root_url(), '', $post_link );

			$full_urls[] = $post_link;
			$uris[] = $post_uri;
			$post = get_post( $post_id );
			$matches =array();
			if ( $post && ( $post_pages_number = preg_match_all( '/\<\!\-\-nextpage\-\-\>/', $post->post_content, $matches ) )>0 ) {
				global $wp_rewrite;
				$post_pages_number++;
				for ( $pagenum = 2; $pagenum <= $post_pages_number; $pagenum++ ) {
					if ( 'page' == get_option( 'show_on_front' ) && get_option( 'page_on_front' ) == $post->ID )
						$post_pagenum_link = trailingslashit( $post_link ) . user_trailingslashit( "$wp_rewrite->pagination_base/" . $pagenum, 'single_paged' );
					else
						$post_pagenum_link = trailingslashit( $post_link ) . user_trailingslashit( $pagenum, 'single_paged' );
					$full_urls[] = $post_pagenum_link;
				}
			}

			$post_urls[$post_id] = $full_urls;
		}
		return $post_urls[$post_id];
	}

	/**
	 * Return full urls for the posts comment pages
	 *
	 * @param unknown $post_id
	 * @return array
	 */
	static public function get_post_comments_urls( $post_id ) {
		static $post_comments_urls = array();

		if ( !isset( $post_comments_urls[$post_id] ) ) {
			$full_urls = array();
			$comments_number = get_comments_number( $post_id );
			$comments_per_page = get_option( 'comments_per_page' );
			$comments_pages_number = @ceil( $comments_number / $comments_per_page );

			for ( $pagenum = 1; $pagenum <= $comments_pages_number; $pagenum++ ) {
				$comments_pagenum_link = self::get_comments_pagenum_link( $post_id, $pagenum );

				$full_urls[] = $comments_pagenum_link;
			}
			$post_comments_urls[$post_id] = $full_urls;
		}
		return $post_comments_urls[$post_id];
	}

	/**
	 * Return full urls for the authors pages
	 *
	 * @param unknown $post_author
	 * @param int     $limit_post_pages default is 10
	 * @return array
	 */
	static public function get_post_author_urls( $post_author, $limit_post_pages = 10 ) {
		static $feed_author_urls = array();

		$key = md5( $post_author . ',' . $limit_post_pages );
		if ( !isset( $post_author_urls[$key] ) ) {
			$full_urls = array();
			$posts_number = count_user_posts( $post_author );
			$posts_per_page = get_option( 'posts_per_page' );
			$posts_pages_number = @ceil( $posts_number / $posts_per_page );

			if ( $limit_post_pages > 0 && $posts_pages_number > $limit_post_pages ) {
				$posts_pages_number = $limit_post_pages;
			}

			$author_link = get_author_posts_url( $post_author );
			$author_uri = str_replace( Util_Environment::home_domain_root_url(), '', $author_link );

			for ( $pagenum = 1; $pagenum <= $posts_pages_number; $pagenum++ ) {
				$author_pagenum_link = self::get_pagenum_link( $author_uri, $pagenum );
				$full_urls[] = $author_pagenum_link;
			}
			$post_author_urls[$key] = $full_urls;
		}
		return $post_author_urls[$key];
	}

	/**
	 * Returns full urls to post terms pages
	 *
	 * @param unknown $terms
	 * @param int     $limit_post_pages default is 10
	 * @return array
	 */
	static public function get_post_terms_urls( $terms, $limit_post_pages = 10 ) {
		static $post_terms_urls = array();

		$key = md5( self::_term_hash( $terms ) . ',' . $limit_post_pages );
		if ( !isset( $post_terms_urls[$key] ) ) {
			$full_urls = array();
			$posts_per_page = get_option( 'posts_per_page' );

			foreach ( $terms as $term ) {
				$term_link = get_term_link( $term, $term->taxonomy );
				$term_uri = str_replace( Util_Environment::home_domain_root_url(), '', $term_link );
				$posts_pages_number = @ceil( $term->count / $posts_per_page );

				if ( $limit_post_pages > 0 && $posts_pages_number > $limit_post_pages ) {
					$posts_pages_number = $limit_post_pages;
				}

				for ( $pagenum = 1; $pagenum <= $posts_pages_number; $pagenum++ ) {
					$term_pagenum_link = self::get_pagenum_link( $term_uri, $pagenum );
					$full_urls[] = $term_pagenum_link;
				}
			}
			$post_terms_urls[$key] = $full_urls;
		}
		return $post_terms_urls[$key];

	}

	/**
	 * Return full urls for daily archive pages based on provided post
	 *
	 * @param unknown $post
	 * @param int     $limit_post_pages default is 10
	 * @return array
	 */
	static public function get_daily_archive_urls( $post, $limit_post_pages = 10 ) {
		static $daily_archive_urls = array();

		$post_type = $post->post_type;
		$archive_slug = self::_get_archive_slug( $post );

		$key = md5( $post->ID . ',' . $limit_post_pages );
		if ( !isset( $daily_archive_urls[$key] ) ) {
			$full_urls = array();
			$post_date = strtotime( $post->post_date );
			$post_year = gmdate( 'Y', $post_date );
			$post_month = gmdate( 'm', $post_date );
			$post_day = gmdate( 'd', $post_date );
			$posts_per_page = get_option( 'posts_per_page' );
			$posts_number = self::get_archive_posts_count( $post_year, $post_month, $post_day, $post_type );
			$posts_pages_number = @ceil( $posts_number / $posts_per_page );

			if ( $limit_post_pages > 0 && $posts_pages_number > $limit_post_pages ) {
				$posts_pages_number = $limit_post_pages;
			}

			$day_link = get_day_link( $post_year, $post_month, $post_day );
			$day_uri = $archive_slug . str_replace( Util_Environment::home_domain_root_url(), '', $day_link );

			for ( $pagenum = 1; $pagenum <= $posts_pages_number; $pagenum++ ) {
				$day_pagenum_link = self::get_pagenum_link( $day_uri, $pagenum );
				$full_urls[] = $day_pagenum_link;
			}
			$daily_archive_urls[$key] = $full_urls;
		}
		return $daily_archive_urls[$key];
	}

	/**
	 * Return full urls for montly archive pages based on provided post
	 *
	 * @param unknown $post
	 * @param int     $limit_post_pages default is 10
	 * @return array
	 */
	static public function get_monthly_archive_urls( $post, $limit_post_pages = 10 ) {
		static $monthly_archive_urls = array();

		$post_type = $post->post_type;
		$archive_slug = self::_get_archive_slug( $post );

		$key = md5( $post->ID . ',' . $limit_post_pages );
		if ( !isset( $monthly_archive_urls[$key] ) ) {
			$full_urls = array();
			$post_date = strtotime( $post->post_date );
			$post_year = gmdate( 'Y', $post_date );
			$post_month = gmdate( 'm', $post_date );

			$posts_per_page = get_option( 'posts_per_page' );
			$posts_number = self::get_archive_posts_count( $post_year, $post_month, '', $post_type );
			$posts_pages_number = @ceil( $posts_number / $posts_per_page );

			if ( $limit_post_pages > 0 && $posts_pages_number > $limit_post_pages ) {
				$posts_pages_number = $limit_post_pages;
			}

			$month_link = get_month_link( $post_year, $post_month );
			$month_uri = $archive_slug . str_replace( Util_Environment::home_domain_root_url(), '', $month_link );

			for ( $pagenum = 1; $pagenum <= $posts_pages_number; $pagenum++ ) {
				$month_pagenum_link = self::get_pagenum_link( $month_uri, $pagenum );
				$full_urls[] = $month_pagenum_link;
			}

			$monthly_archive_urls[$key] = $full_urls;
		}
		return $monthly_archive_urls[$key];
	}

	/**
	 * Return full urls for yearly archive pages based on provided post
	 *
	 * @param unknown $post
	 * @param int     $limit_post_pages default is 10
	 * @return array
	 */
	static public function get_yearly_archive_urls( $post, $limit_post_pages = 10 ) {
		static $yearly_archive_urls = array();

		$post_type = $post->post_type;
		$archive_slug = self::_get_archive_slug( $post );

		$key = md5( $post->ID . ',' . $limit_post_pages );
		if ( !isset( $yearly_archive_urls[$key] ) ) {

			$full_urls = array();
			$post_date = strtotime( $post->post_date );
			$post_year = gmdate( 'Y', $post_date );

			$posts_per_page = get_option( 'posts_per_page' );
			$posts_number =self::get_archive_posts_count( $post_year, '', '', $post_type );
			$posts_pages_number = @ceil( $posts_number / $posts_per_page );

			if ( $limit_post_pages > 0 && $posts_pages_number > $limit_post_pages ) {
				$posts_pages_number = $limit_post_pages;
			}

			$year_link = get_year_link( $post_year );
			$year_uri = $archive_slug . str_replace( Util_Environment::home_domain_root_url(), '', $year_link );

			for ( $pagenum = 1; $pagenum <= $posts_pages_number; $pagenum++ ) {
				$year_pagenum_link = self::get_pagenum_link( $year_uri, $pagenum );
				$full_urls[] = $year_pagenum_link;
			}
			$yearly_archive_urls[$key] = $full_urls;
		}
		return $yearly_archive_urls[$key];
	}

	/**
	 * Return full urls for the provided feed types
	 *
	 * @param unknown $feeds
	 * @param string|null $post_type
	 * @return array
	 */
	static public function get_feed_urls( $feeds, $post_type = null ) {
		static $feed_urls = array();

		$key = md5( implode( ',', $feeds ) . $post_type );
		if ( !isset( $feed_urls[$key] ) ) {
			$full_urls = array();
			foreach ( $feeds as $feed ) {
				$feed_link = self::get_feed_link( $feed, $post_type );

				$full_urls[] = $feed_link;
			}
			$feed_urls[$key] = $full_urls;
		}
		return $feed_urls[$key];
	}

	/**
	 * Return full urls for the provided post id and feed types
	 *
	 * @param unknown $post_id
	 * @param unknown $feeds
	 * @return array
	 */
	static public function get_feed_comments_urls( $post_id, $feeds ) {
		static $feed_comments_urls = array();

		$key = md5( implode( ',', $feeds ) . $post_id );
		if ( !isset( $feed_comments_urls[$key] ) ) {
			$full_urls = array();
			foreach ( $feeds as $feed ) {
				$post_comments_feed_link = self::get_post_comments_feed_link( $post_id, $feed );
				$full_urls[] = $post_comments_feed_link;
			}
			$feed_comments_urls[$key] = $full_urls;
		}
		return $feed_comments_urls[$key];
	}

	/**
	 * Returns full urls for the provided post author and feed types
	 *
	 * @param unknown $post_author
	 * @param unknown $feeds
	 * @return array
	 */
	static public function get_feed_author_urls( $post_author, $feeds ) {
		static $post_author_urls = array();

		$key = md5( implode( ',', $feeds ) . $post_author );
		if ( !isset( $feed_author_urls[$key] ) ) {
			$full_urls = array();
			foreach ( $feeds as $feed ) {
				$author_feed_link = self::get_author_feed_link( $post_author, $feed );
				$full_urls[] = $author_feed_link;
			}
			$feed_author_urls[$key] = $full_urls;
		}
		return $feed_author_urls[$key];
	}

	/**
	 * Returns full urls for the provided terms and feed types
	 *
	 * @param unknown $terms
	 * @param unknown $feeds
	 * @return array
	 */
	static public function get_feed_terms_urls( $terms, $feeds ) {
		static $feed_terms_urls = array();

		$key = md5( implode( ',', $feeds ) . self::_term_hash( $terms ) );
		if ( !isset( $feed_terms_urls[$key] ) ) {
			$full_urls = array();
			foreach ( $terms as $term ) {
				foreach ( $feeds as $feed ) {
					$term_feed_link = self::get_term_feed_link( $term->term_id, $term->taxonomy, $feed );
					$full_urls[] = $term_feed_link;
				}
			}
			$feed_terms_urls[$key] = $full_urls;
		}
		return $feed_terms_urls[$key];
	}

	/**
	 * Returns full urls for the provided url path based pages, ie /some/page.
	 *
	 * @param unknown $pages
	 * @return array
	 */
	static public function get_pages_urls( $pages ) {
		static $pages_urls = array();

		$key = md5( implode( ',', $pages ) );
		if ( !isset( $pages_urls[$key] ) ) {
			$full_urls = array();
			foreach ( $pages as $uri ) {
				if ( $uri ) {
					$page_link = get_home_url() . '/' . trim( $uri, '/' ) .
						( strpos( $uri, '?' ) !== FALSE ? '': '/' );
					$full_urls[] = $page_link;
				}
			}
			$pages_urls[$key] = $full_urls;
		}
		return $pages_urls[$key];
	}

	/**
	 * Workaround for get_pagenum_link function
	 *
	 * @param string  $url
	 * @param int     $pagenum
	 * @return string
	 */
	public static function get_pagenum_link( $url, $pagenum = 1 ) {
		$request_uri            = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$_SERVER['REQUEST_URI'] = $url;

		if ( is_admin() ) {
			$link = self::get_pagenum_link_admin( $pagenum );
		} else {
			$link = get_pagenum_link( $pagenum );
		}

		$_SERVER['REQUEST_URI'] = $request_uri;

		return $link;
	}


	/**
	 * Workaround for get_pagenum_link static public function when in admin
	 *
	 * @param unknown $pagenum
	 * @return string
	 */
	static public function get_pagenum_link_admin( $pagenum ) {
		global $wp_rewrite;

		$pagenum = (int) $pagenum;

		$request = remove_query_arg( 'paged' );

		$home_root = parse_url( home_url() );
		$home_root = ( isset( $home_root['path'] ) ) ? $home_root['path'] : '';
		$home_root = preg_quote( trailingslashit( $home_root ), '|' );

		$request = preg_replace( '|^'. $home_root . '|', '', $request );
		$request = preg_replace( '|^/+|', '', $request );
		$qs_regex = '|\?.*?$|';
		preg_match( $qs_regex, $request, $qs_match );

		if ( !empty( $qs_match[0] ) ) {
			$query_string = $qs_match[0];
			$request = preg_replace( $qs_regex, '', $request );
		} else {
			$query_string = '';
		}

		$request = preg_replace( "|$wp_rewrite->pagination_base/\d+/?$|", '', $request );
		$request = preg_replace( '|^index\.php|', '', $request );
		$request = ltrim( $request, '/' );

		$base = trailingslashit( get_bloginfo( 'url' ) );

		if ( !is_null( $wp_rewrite ) &&
			$wp_rewrite->using_index_permalinks() &&
			( $pagenum > 1 || '' != $request ) )
			$base .= 'index.php/';

		if ( $pagenum > 1 ) {
			$request = ( ( !empty( $request ) ) ? trailingslashit( $request ) : $request ) . user_trailingslashit( $wp_rewrite->pagination_base . "/" . $pagenum, 'paged' );
		}

		$result = $base . $request . $query_string;
		$result = apply_filters( 'get_pagenum_link', $result, $pagenum );
		return $result;
	}

	/**
	 * Workaround for get_comments_pagenum_link function
	 *
	 * @param integer $post_id
	 * @param integer $pagenum
	 * @param integer $max_page
	 * @return string
	 */
	static public function get_comments_pagenum_link( $post_id, $pagenum = 1, $max_page = 0 ) {
		if ( isset( $GLOBALS['post'] ) && is_object( $GLOBALS['post'] ) ) {
			$old_post = &$GLOBALS['post'];
		} else {
			$GLOBALS['post'] = new \stdClass();
			$old_post = null;
		}

		$GLOBALS['post']->ID = $post_id;

		$link = get_comments_pagenum_link( $pagenum, $max_page );

		if ( $old_post ) {
			$GLOBALS['post'] = &$old_post;
		}

		return $link;
	}

	/**
	 * Returns number of posts in the archive.
	 *
	 * @global $wpdb
	 *
	 * @param  int    $year      Year.
	 * @param  int    $month     Month.
	 * @param  int    $day       Day number.
	 * @param  string $post_type Post type.
	 * @return int
	 */
	public static function get_archive_posts_count( $year = 0, $month = 0, $day = 0, $post_type = 'post' ) {
		global $wpdb;

		$filters = array(
			'post_type = "' . $post_type .'"',
			'post_status = "publish"'
		);

		if ( $year ) {
			$filters[] = sprintf( 'YEAR(post_date) = %d', $year );
		}

		if ( $month ) {
			$filters[] = sprintf( 'MONTH(post_date) = %d', $month );
		}

		if ( $day ) {
			$filters[] = sprintf( 'DAY(post_date) = %d', $day );
		}

		$where = implode( ' AND ', $filters );

		$sql = sprintf( 'SELECT COUNT(*) FROM %s WHERE %s', $wpdb->posts, $where );

		$count = (int) $wpdb->get_var( $sql );

		return $count;
	}

	/**
	 * Workaround for get_feed_link function, remove filtering.
	 *
	 * @param string  $feed
	 * @param null|string $post_type
	 * @return mixed
	 */
	static public function get_feed_link( $feed = '', $post_type=null ) {
		/**
		 *
		 *
		 * @var $wp_rewrite WP_Rewrite
		 */
		global $wp_rewrite;

		if ( $post_type )
			return get_post_type_archive_feed_link( $post_type, $feed );

		$permalink = $wp_rewrite->get_feed_permastruct();
		if ( '' != $permalink ) {
			if ( false !== strpos( $feed, 'comments_' ) ) {
				$feed = str_replace( 'comments_', '', $feed );
				$permalink = $wp_rewrite->get_comment_feed_permastruct();
			}

			if ( get_default_feed() == $feed )
				$feed = '';

			$permalink = str_replace( '%feed%', $feed, $permalink );
			$permalink = preg_replace( '#/+#', '/', "/$permalink" );
			$output =  home_url( user_trailingslashit( $permalink, 'feed' ) );
		} else {
			if ( empty( $feed ) )
				$feed = get_default_feed();

			if ( false !== strpos( $feed, 'comments_' ) )
				$feed = str_replace( 'comments_', 'comments-', $feed );

			$output = home_url( "?feed={$feed}" );
		}

		return $output;
	}

	/**
	 * Workaround for get_post_comments_feed_link function, remove filtering.
	 *
	 * @param int     $post_id
	 * @param string  $feed
	 * @return string
	 */
	static public function get_post_comments_feed_link( $post_id = 0, $feed = '' ) {
		$post_id = absint( $post_id );

		if ( ! $post_id )
			$post_id = get_the_ID();

		if ( empty( $feed ) )
			$feed = get_default_feed();

		if ( '' != get_option( 'permalink_structure' ) ) {
			if ( 'page' == get_option( 'show_on_front' ) && $post_id == get_option( 'page_on_front' ) )
				$url = _get_page_link( $post_id );
			else
				$url = get_permalink( $post_id );

			$url = trailingslashit( $url ) . 'feed';
			if ( $feed != get_default_feed() )
				$url .= "/$feed";
			$url = user_trailingslashit( $url, 'single_feed' );
		} else {
			$type = get_post_field( 'post_type', $post_id );
			if ( 'page' == $type )
				$url = home_url( "?feed=$feed&amp;page_id=$post_id" );
			else
				$url = home_url( "?feed=$feed&amp;p=$post_id" );
		}

		return $url;
	}

	/**
	 * Workaround for get_author_feed_link function, remove filtering.
	 *
	 * @param unknown $author_id
	 * @param string  $feed
	 * @return string
	 */
	static public function get_author_feed_link( $author_id, $feed = '' ) {
		$author_id = (int) $author_id;
		$permalink_structure = get_option( 'permalink_structure' );

		if ( empty( $feed ) )
			$feed = get_default_feed();

		if ( '' == $permalink_structure ) {
			$link = home_url( "?feed=$feed&amp;author=" . $author_id );
		} else {
			$link = get_author_posts_url( $author_id );
			if ( $feed == get_default_feed() )
				$feed_link = 'feed';
			else
				$feed_link = "feed/$feed";

			$link = trailingslashit( $link ) . user_trailingslashit( $feed_link, 'feed' );
		}

		return $link;
	}

	/**
	 * Workaround for get_term_feed_link function, remove filtering.
	 *
	 * @param unknown $term_id
	 * @param string  $taxonomy
	 * @param string  $feed
	 * @return bool|string
	 */
	static public function get_term_feed_link( $term_id, $taxonomy = 'category', $feed = '' ) {
		$term_id = ( int ) $term_id;

		$term = get_term( $term_id, $taxonomy  );

		if ( empty( $term ) || is_wp_error( $term ) )
			return false;

		if ( empty( $feed ) )
			$feed = get_default_feed();

		$permalink_structure = get_option( 'permalink_structure' );

		if ( '' == $permalink_structure ) {
			if ( 'category' == $taxonomy ) {
				$link = home_url( "?feed=$feed&amp;cat=$term_id" );
			}
			elseif ( 'post_tag' == $taxonomy ) {
				$link = home_url( "?feed=$feed&amp;tag=$term->slug" );
			} else {
				$t = get_taxonomy( $taxonomy );
				$link = home_url( "?feed=$feed&amp;$t->query_var=$term->slug" );
			}
		} else {
			$link = get_term_link( $term_id, $term->taxonomy );
			if ( $feed == get_default_feed() )
				$feed_link = 'feed';
			else
				$feed_link = "feed/$feed";

			$link = trailingslashit( $link ) . user_trailingslashit( $feed_link, 'feed' );
		}

		return $link;
	}

	static public function get_rest_posts_urls() {
		static $posts_urls = array();

		if ( empty( $posts_urls ) ) {
			$types = get_post_types( array( 'show_in_rest' => true ), 'objects' );
			$wp_json_base = self::wp_json_base();

			foreach ( $types as $post_type ) {
				$rest_base = ( !empty( $post_type->rest_base ) ?
					$post_type->rest_base : $post_type->name );

				$posts_urls[] = $wp_json_base . $rest_base;
			}
		}

		return $posts_urls;
	}

	static public function get_rest_post_urls( $post_id ) {
		static $post_urls = array();

		if ( !isset( $post_urls[$post_id] ) ) {
			$post = get_post( $post_id );
			$urls = array();
			$wp_json_base = self::wp_json_base();

			if ( $post ) {
				$post_type = get_post_type_object( $post->post_type );
				$rest_base = ( !empty( $post_type->rest_base ) ?
					$post_type->rest_base : $post_type->name );

				$urls[] = $wp_json_base . $rest_base . '/' . $post->ID;
			}

			$post_urls[$post_id] = $urls;
		}

		return $post_urls[$post_id];
	}

	static private function wp_json_base() {
		$wp_json_base = rtrim( get_home_url(), '/' ) . W3TC_WP_JSON_URI;
		$wp_json_base = apply_filters( 'w3tc_pageurls_wp_json_base', $wp_json_base );
		return $wp_json_base;
	}

	static public function complement_with_mirror_urls( $queued_urls ) {
		$config = Dispatcher::config();

		if ( !$config->get_boolean( 'pgcache.mirrors.enabled' ) ||
			Util_Environment::is_wpmu_subdomain() )
			return $queued_urls;

		$home_urls = $config->get_array( 'pgcache.mirrors.home_urls' );

		$url_prefix = trailingslashit( get_home_url() );
		$mirror_urls = array();

		foreach ( $queued_urls as $url ) {
			if ( substr( $url, 0, strlen( $url_prefix ) ) != $url_prefix )
				continue;

			foreach ( $home_urls as $home ) {
				if ( !empty( $home ) ) {
					$mirror_urls[] = trailingslashit( $home ) .
						substr( $url, strlen( $url_prefix ) );
				}
			}
		}

		return array_merge( $queued_urls, $mirror_urls );
	}

	static private function _term_hash( $terms ) {
		$term_hash = array();
		foreach ( $terms as $term )
			$term_hash[] = $term->term_id;
		$term_hashed = md5( implode( ',', $term_hash ) );
		return $term_hashed;
	}

	/**
	 *
	 *
	 * @param unknown $post
	 * @return string
	 */
	static private function _get_archive_slug( $post ) {
		$archive_slug = '';
		global $wp_post_types;
		$args = $wp_post_types[$post->post_type];
		if ( $args->has_archive ) {
			global $wp_rewrite;
			$archive_slug = $args->has_archive === true ? $args->rewrite['slug'] : $args->has_archive;
			if ( $args->rewrite['with_front'] )
				$archive_slug = substr( $wp_rewrite->front, 1 ) . $archive_slug;
			else
				$archive_slug = $wp_rewrite->root . $archive_slug;
		}
		return $archive_slug;
	}
}
