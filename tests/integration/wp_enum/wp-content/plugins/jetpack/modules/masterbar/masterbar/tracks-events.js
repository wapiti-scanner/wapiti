( function () {
	'use strict';

	var eventName = 'masterbar_click';

	var linksTracksEvents = {
		//top level items
		'wp-admin-bar-blog': 'my_sites',
		'wp-admin-bar-newdash': 'reader',
		'wp-admin-bar-ab-new-post': 'write_button',
		'wp-admin-bar-my-account': 'my_account',
		'wp-admin-bar-notes': 'notifications',
		//my sites - top items
		'wp-admin-bar-switch-site': 'my_sites_switch_site',
		'wp-admin-bar-blog-info': 'my_sites_blog_info',
		'wp-admin-bar-site-view': 'my_sites_view_site',
		'wp-admin-bar-my-home': 'my_sites_my_home',
		'wp-admin-bar-blog-stats': 'my_sites_blog_stats',
		'wp-admin-bar-activity': 'my_sites_activity',
		'wp-admin-bar-plan': 'my_sites_plan',
		'wp-admin-bar-plan-badge': 'my_sites_plan_badge',
		//my sites - manage
		'wp-admin-bar-edit-page': 'my_sites_manage_site_pages',
		'wp-admin-bar-new-page-badge': 'my_sites_manage_add_page',
		'wp-admin-bar-edit-post': 'my_sites_manage_blog_posts',
		'wp-admin-bar-new-post-badge': 'my_sites_manage_add_new_post',
		'wp-admin-bar-edit-attachment': 'my_sites_manage_media',
		'wp-admin-bar-new-attachment-badge': 'my_sites_manage_add_media',
		'wp-admin-bar-comments': 'my_sites_manage_comments',
		'wp-admin-bar-edit-testimonial': 'my_sites_manage_testimonials',
		'wp-admin-bar-new-testimonial': 'my_sites_manage_add_testimonial',
		'wp-admin-bar-edit-portfolio': 'my_sites_manage_portfolio',
		'wp-admin-bar-new-portfolio': 'my_sites_manage_add_portfolio',
		//my sites - personalize
		'wp-admin-bar-themes': 'my_sites_personalize_themes',
		'wp-admin-bar-cmz': 'my_sites_personalize_themes_customize',
		//my sites - configure
		'wp-admin-bar-sharing': 'my_sites_configure_sharing',
		'wp-admin-bar-people': 'my_sites_configure_people',
		'wp-admin-bar-people-add': 'my_sites_configure_people_add_button',
		'wp-admin-bar-plugins': 'my_sites_configure_plugins',
		'wp-admin-bar-plugins-add': 'my_sites_configure_manage_plugins',
		'wp-admin-bar-blog-settings': 'my_sites_configure_settings',
		//reader
		'wp-admin-bar-followed-sites': 'reader_followed_sites',
		'wp-admin-bar-reader-followed-sites-manage': 'reader_manage_followed_sites',
		'wp-admin-bar-discover-discover': 'reader_discover',
		'wp-admin-bar-discover-search': 'reader_search',
		'wp-admin-bar-my-activity-my-likes': 'reader_my_likes',
		//account
		'wp-admin-bar-user-info': 'my_account_user_name',
		// account - profile
		'wp-admin-bar-my-profile': 'my_account_profile_my_profile',
		'wp-admin-bar-account-settings': 'my_account_profile_account_settings',
		'wp-admin-bar-billing': 'my_account_profile_manage_purchases',
		'wp-admin-bar-security': 'my_account_profile_security',
		'wp-admin-bar-notifications': 'my_account_profile_notifications',
		//account - special
		'wp-admin-bar-get-apps': 'my_account_special_get_apps',
		'wp-admin-bar-next-steps': 'my_account_special_next_steps',
		'wp-admin-bar-help': 'my_account_special_help',
	};

	var notesTracksEvents = {
		openSite: function ( data ) {
			return {
				clicked: 'masterbar_notifications_panel_site',
				site_id: data.siteId,
			};
		},
		openPost: function ( data ) {
			return {
				clicked: 'masterbar_notifications_panel_post',
				site_id: data.siteId,
				post_id: data.postId,
			};
		},
		openComment: function ( data ) {
			return {
				clicked: 'masterbar_notifications_panel_comment',
				site_id: data.siteId,
				post_id: data.postId,
				comment_id: data.commentId,
			};
		},
	};

	function parseJson( s, defaultValue ) {
		try {
			return JSON.parse( s );
		} catch ( e ) {
			return defaultValue;
		}
	}

	// Element.prototype.matches as a standalone function, with old browser fallback
	function matches( node, selector ) {
		if ( ! node ) {
			return undefined;
		}

		if ( ! Element.prototype.matches && ! Element.prototype.msMatchesSelector ) {
			throw new Error( 'Unsupported browser' );
		}

		return Element.prototype.matches
			? node.matches( selector )
			: node.msMatchesSelector( selector );
	}

	// Element.prototype.closest as a standalone function, with old browser fallback
	function closest( node, selector ) {
		if ( ! node ) {
			return undefined;
		}

		if ( Element.prototype.closest ) {
			return node.closest( selector );
		}

		do {
			if ( matches( node, selector ) ) {
				return node;
			}

			node = node.parentElement || node.parentNode;
		} while ( node !== null && node.nodeType === 1 );

		return null;
	}

	function createTrackableLinkEventHandler() {
		return function ( e ) {
			if ( ! window.jpTracksAJAX || typeof window.jpTracksAJAX.record_ajax_event !== 'function' ) {
				return;
			}

			var target = e.target;
			var parent = closest( target, 'li' );

			if ( ! matches( target, 'a' ) ) {
				target = closest( target, 'a' );
			}

			if ( ! parent || ! target ) {
				return;
			}

			var trackingId = target.getAttribute( 'ID' ) || parent.getAttribute( 'ID' );

			if ( ! Object.prototype.hasOwnProperty.call( linksTracksEvents, trackingId ) ) {
				return;
			}
			var eventProps = { clicked: linksTracksEvents[ trackingId ] };

			if ( parent.classList.contains( 'menupop' ) ) {
				window.jpTracksAJAX.record_ajax_event( eventName, 'click', eventProps );
			} else {
				e.preventDefault();
				window.jpTracksAJAX
					.record_ajax_event( eventName, 'click', eventProps )
					.always( function () {
						window.location = target.getAttribute( 'href' );
					} );
			}
		};
	}

	function init() {
		var trackableLinkSelector =
			'.mb-trackable .ab-item:not(div),' +
			'#wp-admin-bar-notes .ab-item,' +
			'#wp-admin-bar-user-info .ab-item,' +
			'.mb-trackable .ab-secondary';

		var trackableLinks = document.querySelectorAll( trackableLinkSelector );
		for ( var i = 0; i < trackableLinks.length; i++ ) {
			var link = trackableLinks[ i ];
			var handler = createTrackableLinkEventHandler();

			link.addEventListener( 'click', handler );
			link.addEventListener( 'touchstart', handler );
		}
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}

	// listen for postMessage events from the notifications iframe
	window.addEventListener(
		'message',
		function ( event ) {
			if ( ! window.jpTracksAJAX || typeof window.jpTracksAJAX.record_ajax_event !== 'function' ) {
				return;
			}

			if ( event.origin !== 'https://widgets.wp.com' ) {
				return;
			}

			var data = typeof event.data === 'string' ? parseJson( event.data, {} ) : event.data;
			if ( data.type !== 'notesIframeMessage' ) {
				return;
			}

			var eventData = notesTracksEvents[ data.action ];
			if ( ! eventData ) {
				return;
			}

			window.jpTracksAJAX.record_ajax_event( eventName, 'click', eventData( data ) );
		},
		false
	);
} )();
