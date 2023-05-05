/**
 * File: setup-guide.js
 *
 * JavaScript for the Setup Guide page.
 *
 * @since 2.0.0
 *
 * @global W3TC-setup-guide Localized array variable.
 */

var w3tc_enable_ga = ( 'accept' === W3TC_SetupGuide.tos_choice && W3TC_SetupGuide.track_usage && window.w3tc_ga );

jQuery(function() {
	var $container = jQuery( '#w3tc-wizard-container'),
		$nextButton = $container.find( '#w3tc-wizard-next '),
		$tosNotice = $container.find( '#w3tc-licensing-terms' );

	// GA.
	if ( w3tc_enable_ga ) {
		w3tc_ga( 'create', W3TC_SetupGuide.ga_profile, 'auto' );
		w3tc_ga( 'send', 'event', 'button', 'w3tc_setup_guide', 'w3tc-wizard-step-welcome' );
	}

	// Handle the terms of service notice.
	if ( $tosNotice.length ) {
		$nextButton.prop( 'disabled', true );
		$container.find( '.dashicons-yes' ).hide();

		$tosNotice.find( '.button' ).on( 'click', function() {
			var $this = jQuery( this ),
				choice = $this.data( 'choice' );

			jQuery.ajax({
				method: 'POST',
				url: ajaxurl,
				data: {
					_wpnonce: $container.find( '[name="_wpnonce"]' ).val(),
					action: "w3tc_tos_choice",
					choice: choice
				}
			})
				.done(function( response ) {
					$tosNotice.hide();
					$nextButton.prop( 'disabled', false );
					$container.find( '#w3tc-welcome' ).show();
					$container.find( '.dashicons-yes' ).show();
				})
				.fail(function() {
					$this.text( 'Error with Ajax; reloading page...' );

					location.reload();
				});

			if ( 'accept' === choice ) {
				W3TC_SetupGuide.tos_choice = choice;

				(function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
					(i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
					m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
					})(window,document,'script','https://api.w3-edge.com/v1/analytics','w3tc_ga');

				if (window.w3tc_ga) {
					w3tc_ga( 'create', W3TC_SetupGuide.ga_profile, 'auto' );
					w3tc_ga( 'set', {
						'dimension1': 'w3-total-cache',
						'dimension2': W3TC_SetupGuide.w3tc_version,
						'dimension3': W3TC_SetupGuide.wp_version,
						'dimension4': W3TC_SetupGuide.php_version,
						'dimension5': W3TC_SetupGuide.server_software,
						'dimension6': W3TC_SetupGuide.db_version,
						'dimension7': W3TC_SetupGuide.home_url_host,
						'dimension9': W3TC_SetupGuide.install_version,
						'dimension10': W3TC_SetupGuide.w3tc_edition,
						'dimension11': W3TC_SetupGuide.list_widgets,
						'page': W3TC_SetupGuide.page
					});

					w3tc_ga( 'send', 'pageview' );
				}
			}
		});
	}
});

jQuery( '#w3tc-wizard-step-welcome' )
	.addClass( 'is-active' )
	.append( '<span class="dashicons dashicons-yes"></span>' );

 /**
  * Wizard actions.
  *
  * @since 2.0.0
  *
  * @param object $slide The div of the slide displayed.
  */
function w3tc_wizard_actions( $slide ) {
	var configSuccess = false,
		pgcacheSettings = {
			enabled: null,
			engine: null
		},
		dbcacheSettings = {
			enabled: null,
			engine: null
		},
		objcacheSettings = {
			enabled: null,
			engine: null
		},
		browsercacheSettings = {
			enabled: null
		},
		lazyloadSettings = {
			enabled: null
		},
		slideId = $slide.prop( 'id' ),
		$container = jQuery( '#w3tc-wizard-container' ),
		nonce = $container.find( '[name="_wpnonce"]' ).val(),
		$nextButton = $container.find( '#w3tc-wizard-next' ),
		$prevButton = $container.find( '#w3tc-wizard-previous' ),
		$skipButton = $container.find( '#w3tc-wizard-skip' ),
		$dashboardButton = $container.find( '#w3tc-wizard-dashboard' );

	/**
	 * Configure Page Cache.
	 *
	 * @since 2.0.0
	 *
	 * @param int    enable Enable Page Cache.
	 * @param string engine Page Cache storage engine.
	 * @return jqXHR
	 */
	function configPgcache( enable, engine = '' ) {
		var $jqXHR = jQuery.ajax({
			method: 'POST',
			url: ajaxurl,
			data: {
				_wpnonce: nonce,
				action: 'w3tc_config_pgcache',
				enable: enable,
				engine: engine
			}
		});

		configSuccess = null;

		$jqXHR.done(function( response ) {
			configSuccess = response.data.success;
		});

		return $jqXHR;
	}

	/**
	 * Get Page Cache settings.
	 *
	 * @since 2.0.0
	 *
	 * @return jqXHR
	 */
	function getPgcacheSettings() {
		return jQuery.ajax({
			method: 'POST',
			url: ajaxurl,
			data: {
				_wpnonce: nonce,
				action: 'w3tc_get_pgcache_settings'
			}
		})
		.done(function( response ) {
			pgcacheSettings = response.data;
		});
	}

	/**
	 * Configure Database Cache.
	 *
	 * @since 2.0.0
	 *
	 * @param int    enable Enable database cache.
	 * @param string engine Database cache storage engine.
	 * @return jqXHR
	 */
	function configDbcache( enable, engine = '' ) {
		var $jqXHR = jQuery.ajax({
			method: 'POST',
			url: ajaxurl,
			data: {
				_wpnonce: nonce,
				action: 'w3tc_config_dbcache',
				enable: enable,
				engine: engine
			}
		});

		configSuccess = null;

		$jqXHR.done(function( response ) {
			configSuccess = response.data.success;
		});

		return $jqXHR;
	}

	/**
	 * Get Database Cache settings.
	 *
	 * @since 2.0.0
	 *
	 * @return jqXHR
	 */
	function getDbcacheSettings() {
		return jQuery.ajax({
			method: 'POST',
			url: ajaxurl,
			data: {
				_wpnonce: nonce,
				action: 'w3tc_get_dbcache_settings'
			}
		})
		.done(function( response ) {
			dbcacheSettings = response.data;
		});
	}

	/**
	 * Configure Object Cache.
	 *
	 * @since 2.0.0
	 *
	 * @param int    enable Enable cache.
	 * @param string engine Cache storage engine.
	 * @return jqXHR
	 */
	function configObjcache( enable, engine = '' ) {
		var $jqXHR = jQuery.ajax({
			method: 'POST',
			url: ajaxurl,
			data: {
				_wpnonce: nonce,
				action: 'w3tc_config_objcache',
				enable: enable,
				engine: engine
			}
		});

		configSuccess = null;

		$jqXHR.done(function( response ) {
			configSuccess = response.data.success;
		});

		return $jqXHR;
	}

	/**
	 * Get Object Cache settings.
	 *
	 * @since 2.0.0
	 *
	 * @return jqXHR
	 */
	function getObjcacheSettings() {
		return jQuery.ajax({
			method: 'POST',
			url: ajaxurl,
			data: {
				_wpnonce: nonce,
				action: 'w3tc_get_objcache_settings'
			}
		})
		.done(function( response ) {
			objcacheSettings = response.data;
		});
	}

	/**
	 * Configure Browser Cache.
	 *
	 * @since 2.0.0
	 *
	 * @param int enable Enable browser cache.
	 * @return jqXHR
	 */
	function configBrowsercache( enable ) {
		configSuccess = null;

		return jQuery.ajax({
			method: 'POST',
			url: ajaxurl,
			data: {
				_wpnonce: nonce,
				action: 'w3tc_config_browsercache',
				enable: enable
			}
		})
		.done(function( response ) {
			configSuccess = response.data.success;
		});
	}

	/**
	 * Get Browser Cache settings.
	 *
	 * @since 2.0.0
	 *
	 * @return jqXHR
	 */
	function getBrowsercacheSettings() {
		return jQuery.ajax({
			method: 'POST',
			url: ajaxurl,
			data: {
				_wpnonce: nonce,
				action: 'w3tc_get_browsercache_settings'
			}
		})
		.done(function( response ) {
			browsercacheSettings = response.data;
		});
	}

	/**
	 * Configure Lazy Load.
	 *
	 * @since 2.0.0
	 *
	 * @param int enable Enable lazyload.
	 * @return jqXHR
	 */
	function configLazyload( enable ) {
		configSuccess = null;

		return jQuery.ajax({
			method: 'POST',
			url: ajaxurl,
			data: {
				_wpnonce: nonce,
				action: 'w3tc_config_lazyload',
				enable: enable
			}
		})
		.done(function( response ) {
			configSuccess = response.data.success;
		});
	}

	/**
	 * Get Lazt Load settings.
	 *
	 * @since 2.0.0
	 *
	 * @return jqXHR
	 */
	function getLazyloadSettings() {
		return jQuery.ajax({
			method: 'POST',
			url: ajaxurl,
			data: {
				_wpnonce: nonce,
				action: 'w3tc_get_lazyload_settings'
			}
		})
		.done(function( response ) {
			lazyloadSettings = response.data;
		});
	}

	/**
	 * Configuration failed.
	 *
	 * @since 2.0.0
	 */
	function configFailed() {
		$slide.append(
			'<div class="notice notice-error"><p><strong>' +
			W3TC_SetupGuide.config_error_msg +
			'</strong></p></div>'
		);
		$nextButton.closest( 'span' ).hide();
		$prevButton.closest( 'span' ).hide();
		$skipButton.closest( 'span' ).show();
	}

	/**
	 * Test failed.
	 *
	 * @since 2.0.0
	 */
	function testFailed() {
		$slide.append(
			'<div class="notice notice-error"><p><strong>' +
			W3TC_SetupGuide.config_error_msg +
			'</strong></p></div>'
		);
		$nextButton.closest( 'span' ).hide();
		$prevButton.closest( 'span' ).hide();
		$skipButton.closest( 'span' ).show();
	}

	// GA.
	if ( w3tc_enable_ga ) {
		w3tc_ga( 'send', 'event', 'button', 'w3tc_setup_guide', slideId );
	}

	switch ( slideId ) {
		case 'w3tc-wizard-slide-welcome':
			$container.find( '#w3tc-options-menu li' ).removeClass( 'is-active' );
			$container.find( '#w3tc-wizard-step-welcome' ).addClass( 'is-active' );

			break;

		case 'w3tc-wizard-slide-pc1':
			// Test Page Cache.
			$container.find( '#w3tc-options-menu li' ).removeClass( 'is-active' );
			$container.find( '#w3tc-wizard-step-pgcache' ).addClass( 'is-active' );

			if ( ! $container.find( '#test-results' ).data( 'pgcache-none' ) ) {
				$nextButton.prop( 'disabled', 'disabled' );
			}

			$slide.find( '#w3tc-test-pgcache' ).off('click').on('click', function () {
				var $spinnerParent = $slide.find( '.spinner' ).addClass( 'is-active' ).parent(),
					$this = jQuery( this );

				$this.prop( 'disabled', 'disabled' );
				$slide.find( '.notice-error' ).remove();
				$container.find( '#w3tc-pgcache-table tbody' ).empty();
				$prevButton.prop( 'disabled', 'disabled' );
				$nextButton.prop( 'disabled', 'disabled' );

				$spinnerParent.show();

				/**
				 * Add a test result table row.
				 *
				 * @since 2.0.0
				 *
				 * @param object testResponse Data.
				 * @param string engine       Cache storage engine.
				 * @param string label        Text label for the engine.
				 */
				function addResultRow( testResponse, engine, label ) {
					var baseline,
						results = '<tr',
						percentChange,
						changeLabelType,
						changeLabel,
						isCurrentSetting = ( ! pgcacheSettings.enabled && 'none' === engine ) ||
							( pgcacheSettings.enabled && pgcacheSettings.engine === engine );

					if ( ! configSuccess ) {
						results += ' class="w3tc-option-disabled"';
					}

					results += '><td><input type="radio" id="pgcache-engine-' +
						engine +
						'" name="pgcache_engine" value="' +
						engine +
						'"';

					if ( ! configSuccess ) {
						results += ' disabled="disabled"';
					}

					if ( isCurrentSetting ) {
						results += ' checked';
					}

					if ( configSuccess && 'file_generic' === engine ) {
						label += '<br /><span class="w3tc-option-recommended">(Recommended)</span>';
					}

					results += '>';

					if ( isCurrentSetting ) {
						results += '<span class="dashicons dashicons-admin-settings" title="Current setting"></span>';
					}

					results += '</td><td><label for="pgcache-engine-' +
						engine +
						'">' +
						label +
						'</label></td><td>';

					if ( testResponse.success ) {
						results += ( testResponse.data.ttfb * 1000 ).toFixed( 2 );
						if ( 'none' !== engine ) {
							baseline = $container.find( '#test-results' ).data( 'pgcache-none' ).ttfb;
							percentChange = ( ( testResponse.data.ttfb - baseline ) / baseline * 100 ).toFixed( 2 );
							changeLabelType = percentChange < 0 ? 'w3tc-label-success' : 'w3tc-label-danger';
							changeLabel = '<span class="w3tc-label ' + changeLabelType + '">' + percentChange + '%</span>';

							$container.find( '#test-results' ).data( 'pgcacheDiffPercent-' + engine, percentChange );
							results += ' ' + changeLabel;
						}
					} else {
						results += W3TC_SetupGuide.unavailable_text;
					}

					results += '</td></tr>';

					$container.find( '#w3tc-pgcache-table tbody' ).append( results );
					$container.find( '#w3tc-pgcache-table' ).show();
				}

				/**
				 * Test Page Cache.
				 *
				 * @since 2.0.0
				 *
				 * @param string engine Cache storage engine.
				 * @param string label  Text label for the engine.
				 * @return jqXHR
				 */
				function testPgcache( engine, label ) {
					if ( configSuccess ) {
						return jQuery.ajax({
							method: 'POST',
							url: ajaxurl,
							data: {
								_wpnonce: nonce,
								action: 'w3tc_test_pgcache'
							}
						})
						.done(function( testResponse ) {
							$container.find( '#test-results' ).data( 'pgcache-' + engine, testResponse.data );
							addResultRow( testResponse, engine, label );
						});
					} else {
						addResultRow( [ success => false ], engine, label );
					}
				}

				// Run config and tests.
				getPgcacheSettings()
					.then( function() {
						return configPgcache( 0 );
					}, configFailed )
					.then( function() {
						return testPgcache( 'none', W3TC_SetupGuide.none );
					}, configFailed )
					.then( function() {
						return configPgcache( 1, 'file' );
					} , testFailed )
					.then( function() {
						return testPgcache( 'file', W3TC_SetupGuide.disk_basic );
					}, configFailed )
					.then( function() {
						return configPgcache( 1, 'file_generic' );
					} , testFailed )
					.then( function() {
						return testPgcache( 'file_generic', W3TC_SetupGuide.disk_enhanced );
					}, configFailed )
					.then( function() {
						return configPgcache( 1, 'redis' );
					}, testFailed )
					.then( function() {
						return testPgcache( 'redis', 'Redis' );
					}, configFailed )
					.then( function() {
						return configPgcache( 1, 'memcached' );
					}, testFailed )
					.then( function() {
						return testPgcache( 'memcached', 'Memcached' );
					}, configFailed )
					.then( function() {
						return configPgcache( 1, 'apc' );
					}, testFailed )
					.then( function() {
						return testPgcache( 'apc', 'APC' );
					}, configFailed )
					.then( function() {
						return configPgcache( 1, 'eaccelerator' );
					}, testFailed )
					.then( function() {
						return testPgcache( 'eaccelerator', 'eAccelerator' );
					}, configFailed )
					.then( function() {
						return configPgcache( 1, 'xcache' );
					}, testFailed )
					.then( function() {
						return testPgcache( 'xcache', 'XCache' );
					}, configFailed )
					.then( function() {
						return configPgcache( 1, 'wincache' );
					}, testFailed )
					.then( function() {
						return testPgcache( 'wincache', 'WinCache' );
					}, configFailed )
					.then(function() {
						$spinnerParent.hide();
						$this.prop( 'disabled', false );
						$prevButton.prop( 'disabled', false );
						$nextButton.prop( 'disabled', false );
						return true;
					}, testFailed )
					// Restore the original database cache settings.
					.then( function() {
						return configPgcache( ( pgcacheSettings.enabled ? 1 : 0 ), pgcacheSettings.engine );
					},
					function() {
						$spinnerParent.hide();
						return configFailed();
					});
			});

			break;

		case 'w3tc-wizard-slide-dbc1':
			// Save the page cache engine setting from the previous slide.
			var pgcacheEngine = $container.find( 'input:checked[name="pgcache_engine"]' ).val();

			configPgcache( ( 'none' === pgcacheEngine ? 0 : 1 ), 'none' === pgcacheEngine ? '' : pgcacheEngine )
				.fail( function() {
					$slide.append(
						'<div class="notice notice-error"><p><strong>' +
						W3TC_SetupGuide.config_error_msg +
						'</strong></p></div>'
					);
				});

			if ( ! jQuery( '#w3tc-wizard-step-pgcache .dashicons-yes' ).length ) {
				jQuery( '#w3tc-wizard-step-pgcache' ).append( '<span class="dashicons dashicons-yes"></span>' );
			}

			// Present the Database Cache slide.
			$container.find( '#w3tc-options-menu li' ).removeClass( 'is-active' );
			$container.find( '#w3tc-wizard-step-dbcache' ).addClass( 'is-active' );

			if ( ! $container.find( '#test-results' ).data( 'dbc-none' ) ) {
				$nextButton.prop( 'disabled', 'disabled' );
			}

			$slide.find( '#w3tc-test-dbcache' ).off('click').on('click', function () {
				var $spinnerParent = $slide.find( '.spinner' ).addClass( 'is-active' ).parent(),
					$this = jQuery( this );

				$this.prop( 'disabled', 'disabled' );
				$slide.find( '.notice-error' ).remove();
				$container.find( '#w3tc-dbc-table tbody' ).empty();
				$container.find( '#w3tc-dbcache-recommended' ).hide();
				$prevButton.prop( 'disabled', 'disabled' );
				$nextButton.prop( 'disabled', 'disabled' );

				$spinnerParent.show();

				/**
				 * Add a test result table row.
				 *
				 * @since 2.0.0
				 *
				 * @param object testResponse Data.
				 * @param string engine       Cache storage engine.
				 * @param string label        Text label for the engine.
				 */
				function addResultRow( testResponse, engine, label ) {
					var baseline,
						results = '<tr',
						percentChange,
						changeLabelType,
						changeLabel,
						isCurrentSetting = ( ! dbcacheSettings.enabled && 'none' === engine ) ||
							( dbcacheSettings.enabled && dbcacheSettings.engine === engine );

					if ( ! configSuccess ) {
						results += ' class="w3tc-option-disabled"';
					}

					results += '><td><input type="radio" id="dbcache-engine-' +
						engine +
						'" name="dbcache_engine" value="' +
						engine +
						'"';

					if ( ! configSuccess ) {
						results += ' disabled="disabled"';
					}

					if ( isCurrentSetting ) {
							results += ' checked';
					}

					results += '>';

					if ( isCurrentSetting ) {
						results += '<span class="dashicons dashicons-admin-settings" title="Current setting"></span>';
					}

					results += '</td><td><label for="dbcache-engine-' +
						engine +
						'">' +
						label +
						'</label></td><td>';

					if ( testResponse.success ) {
						results += ( testResponse.data.elapsed * 1000 ).toFixed( 2 );

						if ( 'none' !== engine ) {
							baseline = $container.find( '#test-results' ).data( 'dbc-none' ).elapsed;
							percentChange = ( ( testResponse.data.elapsed - baseline ) / baseline * 100 ).toFixed( 2 );
							changeLabelType = percentChange < 0 ? 'w3tc-label-success' : 'w3tc-label-danger';
							changeLabel = '<span class="w3tc-label ' + changeLabelType + '">'+ percentChange + '%</span>';

							results += ' ' + changeLabel;
						}
					} else {
						results += W3TC_SetupGuide.unavailable_text;
					}

					results += '</td></tr>';

					$container.find( '#w3tc-dbc-table tbody' ).append( results );
					$container.find( '#w3tc-dbc-table' ).show();
				}

				/**
				 * Test database cache.
				 *
				 * @since 2.0.0
				 *
				 * @param string engine Cache storage engine.
				 * @param string label  Text label for the engine.
				 * @return jqXHR
				 */
				function testDbcache( engine, label ) {
					if ( configSuccess ) {
						return jQuery.ajax({
							method: 'POST',
							url: ajaxurl,
							data: {
								_wpnonce: nonce,
								action: 'w3tc_test_dbcache'
							}
						})
						.done(function( testResponse ) {
							$container.find( '#test-results' ).data( 'dbc-' + engine, testResponse.data );
							addResultRow( testResponse, engine, label );
						});
					} else {
						addResultRow( [ success => false ], engine, label );
					}
				}

				// Run config and tests.
				getDbcacheSettings()
					.then( function() {
						return configDbcache( 0 );
					}, configFailed )
					.then( function() {
						return testDbcache( 'none', W3TC_SetupGuide.none );
					}, configFailed )
					.then( function() {
						return configDbcache( 1, 'file' );
					} , testFailed )
					.then( function() {
						return testDbcache( 'file', W3TC_SetupGuide.disk );
					}, configFailed )
					.then( function() {
						return configDbcache( 1, 'redis' );
					}, testFailed )
					.then( function() {
						return testDbcache( 'redis', 'Redis' );
					}, configFailed )
					.then( function() {
						return configDbcache( 1, 'memcached' );
					}, testFailed )
					.then( function() {
						return testDbcache( 'memcached', 'Memcached' );
					}, configFailed )
					.then( function() {
						return configDbcache( 1, 'apc' );
					}, testFailed )
					.then( function() {
						return testDbcache( 'apc', 'APC' );
					}, configFailed )
					.then( function() {
						return configDbcache( 1, 'eaccelerator' );
					}, testFailed )
					.then( function() {
						return testDbcache( 'eaccelerator', 'eAccelerator' );
					}, configFailed )
					.then( function() {
						return configDbcache( 1, 'xcache' );
					}, testFailed )
					.then( function() {
						return testDbcache( 'xcache', 'XCache' );
					}, configFailed )
					.then( function() {
						return configDbcache( 1, 'wincache' );
					}, testFailed )
					.then( function() {
						return testDbcache( 'wincache', 'WinCache' );
					}, configFailed )
					.then(function() {
						$spinnerParent.hide();
						$this.prop( 'disabled', false );
						$prevButton.prop( 'disabled', false );
						$nextButton.prop( 'disabled', false );
						return true;
					}, testFailed )
					.then( function() {
						$container.find( '#w3tc-dbcache-recommended' ).show();
						// Restore the original database cache settings.
						return configDbcache( ( dbcacheSettings.enabled ? 1 : 0 ), dbcacheSettings.engine );
					},
					function() {
						$spinnerParent.hide();
						return configFailed();
					});
			});

			break;

		case 'w3tc-wizard-slide-oc1':
			// Save the database cache engine setting from the previous slide.
			var dbcEngine = $container.find( 'input:checked[name="dbcache_engine"]' ).val();

			configDbcache( ( 'none' === dbcEngine ? 0 : 1 ), 'none' === dbcEngine ? '' : dbcEngine )
				.fail( function() {
					$slide.append(
						'<div class="notice notice-error"><p><strong>' +
						W3TC_SetupGuide.config_error_msg +
						'</strong></p></div>'
					);
				});

			if ( ! jQuery( '#w3tc-wizard-step-dbcache .dashicons-yes' ).length ) {
				jQuery( '#w3tc-wizard-step-dbcache' ).append( '<span class="dashicons dashicons-yes"></span>' );
			}

			// Present the Object Cache slide.
			$container.find( '#w3tc-options-menu li' ).removeClass( 'is-active' );
			$container.find( '#w3tc-wizard-step-objectcache' ).addClass( 'is-active' );

			if ( ! $container.find( '#test-results' ).data( 'oc-none' ) ) {
				$nextButton.prop( 'disabled', 'disabled' );
			}

			$slide.find( '#w3tc-test-objcache' ).off('click').on('click', function () {
				var $spinnerParent = $slide.find( '.spinner' ).addClass( 'is-active' ).parent(),
					$this = jQuery( this );

				$this.prop( 'disabled', 'disabled' );
				$slide.find( '.notice-error' ).remove();
				$container.find( '#w3tc-objcache-table tbody' ).empty();
				$prevButton.prop( 'disabled', 'disabled' );
				$nextButton.prop( 'disabled', 'disabled' );

				$spinnerParent.show();

				/**
				 * Add a test result table row.
				 *
				 * @since 2.0.0
				 *
				 * @param object testResponse Data.
				 * @param string engine       Cache storage engine.
				 * @param string label        Text label for the engine.
				 */
				function addResultRow( testResponse, engine, label ) {
					var baseline,
						results = '<tr',
						percentChange,
						changeLabelType,
						changeLabel,
						isCurrentSetting = ( ! objcacheSettings.enabled && 'none' === engine ) ||
							( objcacheSettings.enabled && objcacheSettings.engine === engine );

					if ( ! configSuccess ) {
						results += ' class="w3tc-option-disabled"';
					}

					results += '><td><input type="radio" id="objcache-engine-' +
						engine +
						'" name="objcache_engine" value="' +
						engine +
						'"';

					if ( ! configSuccess ) {
						results += ' disabled="disabled"';
					}

					if ( isCurrentSetting ) {
							results += ' checked';
					}

					results += '>';

					if ( isCurrentSetting ) {
						results += '<span class="dashicons dashicons-admin-settings" title="Current setting"></span>';
					}

					results += '</td><td><label for="objcache-engine-' +
						engine +
						'">' +
						label +
						'</label></td><td>';

					if ( testResponse.success ) {
						results += ( testResponse.data.elapsed * 1000 ).toFixed( 2 );
						if ( 'none' !== engine ) {
							baseline = $container.find( '#test-results' ).data( 'oc-none' ).elapsed;
							percentChange = ( ( testResponse.data.elapsed - baseline ) / baseline * 100 ).toFixed( 2 );
							changeLabelType = percentChange < 0 ? 'w3tc-label-success' : 'w3tc-label-danger';
							changeLabel = '<span class="w3tc-label ' + changeLabelType + '">' + percentChange + '%</span>';

							results += ' ' + changeLabel;
						}
					} else {
						results += W3TC_SetupGuide.unavailable_text;
					}

					results += '</td></tr>';

					$container.find( '#w3tc-objcache-table tbody' ).append( results );
					$container.find( '#w3tc-objcache-table' ).show();
				}

				/**
				 * Test object cache cache.
				 *
				 * @since 2.0.0
				 *
				 * @param string engine Cache storage engine.
				 * @param string label  Text label for the engine.
				 * @return jqXHR
				 */
				function testObjcache( engine, label ) {
					if ( configSuccess ) {
						return jQuery.ajax({
							method: 'POST',
							url: ajaxurl,
							data: {
								_wpnonce: nonce,
								action: 'w3tc_test_objcache'
							}
						})
						.done(function( testResponse ) {
							$container.find( '#test-results' ).data( 'oc-' + engine, testResponse.data );
							addResultRow( testResponse, engine, label );
						});
					} else {
						addResultRow( [ success => false ], engine, label );
					}
				}

				// Run config and tests.
				getObjcacheSettings()
					.then( function() {
						return configObjcache( 0 );
					}, configFailed )
					.then( function() {
						return testObjcache( 'none', W3TC_SetupGuide.none );
					}, configFailed )
					.then( function() {
						return configObjcache( 1, 'file' );
					} , testFailed )
					.then( function() {
						return testObjcache( 'file', W3TC_SetupGuide.disk );
					}, configFailed )
					.then( function() {
						return configObjcache( 1, 'redis' );
					}, testFailed )
					.then( function() {
						return testObjcache( 'redis', 'Redis' );
					}, configFailed )
					.then( function() {
						return configObjcache( 1, 'memcached' );
					}, testFailed )
					.then( function() {
						return testObjcache( 'memcached', 'Memcached' );
					}, configFailed )
					.then( function() {
						return configObjcache( 1, 'apc' );
					}, testFailed )
					.then( function() {
						return testObjcache( 'apc', 'APC' );
					}, configFailed )
					.then( function() {
						return configObjcache( 1, 'eaccelerator' );
					}, testFailed )
					.then( function() {
						return testObjcache( 'eaccelerator', 'eAccelerator' );
					}, configFailed )
					.then( function() {
						return configObjcache( 1, 'xcache' );
					}, testFailed )
					.then( function() {
						return testObjcache( 'xcache', 'XCache' );
					}, configFailed )
					.then( function() {
						return configObjcache( 1, 'wincache' );
					}, testFailed )
					.then( function() {
						return testObjcache( 'wincache', 'WinCache' );
					}, configFailed )
					.then(function() {
						$spinnerParent.hide();
						$this.prop( 'disabled', false );
						$prevButton.prop( 'disabled', false );
						$nextButton.prop( 'disabled', false );
						return true;
					}, testFailed )
					// Restore the original object cache settings.
					.then( function() {
						return configObjcache( ( objcacheSettings.enabled ? 1 : 0 ), objcacheSettings.engine );
					},
					function() {
						$spinnerParent.hide();
						return configFailed();
					});
			});

			break;

		case 'w3tc-wizard-slide-bc1':
			// Save the object cache engine setting from the previous slide.
			var objcacheEngine = $container.find( 'input:checked[name="objcache_engine"]' ).val();

			configObjcache( ( 'none' === objcacheEngine ? 0 : 1 ), 'none' === objcacheEngine ? '' : objcacheEngine )
				.fail( function() {
					$slide.append(
						'<div class="notice notice-error"><p><strong>' +
						W3TC_SetupGuide.config_error_msg +
						'</strong></p></div>'
					);
				});

			if ( ! jQuery( '#w3tc-wizard-step-objectcache .dashicons-yes' ).length ) {
				jQuery( '#w3tc-wizard-step-objectcache' ).append( '<span class="dashicons dashicons-yes"></span>' );
			}

			// Present the Browser Cache slide.
			$container.find( '#w3tc-options-menu li' ).removeClass( 'is-active' );
			$container.find( '#w3tc-wizard-step-browsercache' ).addClass( 'is-active' );

			if ( ! $container.find( '#test-results' ).data( 'bc-off' ) ) {
				$nextButton.prop( 'disabled', 'disabled' );
			}

			$slide.find( '#w3tc-test-browsercache' ).off('click').on('click', function () {
				var bcEnabled,
					$spinnerParent = $slide.find( '.spinner' ).addClass( 'is-active' ).parent(),
					$this = jQuery( this );

				$this.prop( 'disabled', 'disabled' );
				$slide.find( '.notice-error' ).remove();
				$container.find( '#w3tc-browsercache-table tbody' ).empty();
				$prevButton.prop( 'disabled', 'disabled' );
				$nextButton.prop( 'disabled', 'disabled' );

				$spinnerParent.show();

				/**
				 * Add a Browser Cache test result table row.
				 *
				 * @since 2.0.0
				 *
				 * @param object testResponse An object (success, data) containing a data array of objects
				 * 	                          (url, filename, header, headers).
				 */
				function addResultRow( testResponse ) {
					var label = bcEnabled ? W3TC_SetupGuide.enabled : W3TC_SetupGuide.notEnabled,
						results = '<tr',
						isCurrentSetting = bcEnabled == browsercacheSettings.enabled;

					if ( ! configSuccess ) {
						results += ' class="w3tc-option-disabled"';
					}

					results += '><td><input type="radio" id="browsercache-enable-' +
						label +
						'" name="browsercache_enable" value="' +
						bcEnabled +
						'"';

					if ( ! configSuccess ) {
						results += ' disabled="disabled"';
					}

					if ( isCurrentSetting ) {
						results += ' checked';
					}

					results += '> <label for="browsercache-enable-' +
						label +
						'">' +
						label +
						'</label>';

					if ( isCurrentSetting ) {
						results += ' <span class="dashicons dashicons-admin-settings" title="Current setting"></span>';
					}

					results += '</td>';

					if ( testResponse.success ) {
						results += '<td>';

						testResponse.data.forEach( function( item, index ) {
							results += '<a href="' +
							item.url +
							'">' +
							item.filename +
							'</a></td><td>' +
							item.header +
							'</td></tr>';

							// If not the last entry, then start the next row.
							if ( index !== ( testResponse.data.length - 1 ) ) {
								results += '<tr><td></td><td>';
							}
						} );
					} else {
						results = '<td colspan="2">' +
							W3TC_SetupGuide.test_error_msg +
							'</td></tr>';
					}

					$container.find( '#w3tc-browsercache-table > tbody' ).append( results );
					$container.find( '#w3tc-browsercache-table' ).show();
				}

				/**
				 * Test browser cache.
				 *
				 * @since 2.0.0
				 *
				 * @return jqXHR
				 */
				function testBrowsercache() {
					if ( configSuccess ) {
						return jQuery.ajax({
							method: 'POST',
							url: ajaxurl,
							data: {
								_wpnonce: nonce,
								action: 'w3tc_test_browsercache'
							}
						})
						.done(function( testResponse ) {
							var enabled = bcEnabled ? 'on' : 'off';

							$container.find( '#test-results' ).data( 'bc-' + enabled, testResponse.data );
							addResultRow( testResponse );
						});
					} else {
						addResultRow( [ success => false ] );
					}
				}

				// Run config and tests.
				getBrowsercacheSettings()
					.then( function() {
						bcEnabled = 0;
						return configBrowsercache( bcEnabled );
					}, configFailed )
					.then( testBrowsercache, configFailed )
					.then( function() {
						bcEnabled = 1;
						return configBrowsercache( bcEnabled );
					} , testFailed )
					.then( testBrowsercache, configFailed )
					.then(function() {
						$spinnerParent.hide();
						$this.prop( 'disabled', false );
						$prevButton.prop( 'disabled', false );
						$nextButton.prop( 'disabled', false );
						return true;
					}, testFailed )
					// Restore the original browser cache settings.
					.then( function() {
						return configBrowsercache( ( browsercacheSettings.enabled ? 1 : 0 ) );
					},
					function() {
						$spinnerParent.hide();
						return configFailed();
					});
			});

			break;

		case 'w3tc-wizard-slide-ll1':
			// Save the browser cache setting from the previous slide.
			var browsercacheEnabled = $container.find( 'input:checked[name="browsercache_enable"]' ).val();

			configBrowsercache( ( '1' === browsercacheEnabled ? 1 : 0 ) )
				.fail( function() {
					$slide.append(
						'<div class="notice notice-error"><p><strong>' +
						W3TC_SetupGuide.config_error_msg +
						'</strong></p></div>'
					);
				});

			if ( ! jQuery( '#w3tc-wizard-step-browsercache .dashicons-yes' ).length ) {
				jQuery( '#w3tc-wizard-step-browsercache' ).append( '<span class="dashicons dashicons-yes"></span>' );
			}

			// Present the Lazy Load slide.
			$container.find( '#w3tc-options-menu li' ).removeClass( 'is-active' );
			$container.find( '#w3tc-wizard-step-lazyload' ).addClass( 'is-active' );
			$dashboardButton.closest( 'span' ).hide();
			$nextButton.closest( 'span' ).show();
			$nextButton.prop( 'disabled', 'disabled' );

			// Update the lazy load enable chackbox from saved config.
			getLazyloadSettings()
				.then( function() {
					$container.find( 'input#lazyload-enable' ).prop( 'checked', lazyloadSettings.enabled );
					$nextButton.prop( 'disabled', false );
				}, configFailed );

			break;

		case 'w3tc-wizard-slide-complete':
			var html,
				pgcacheEngine = $container.find( 'input:checked[name="pgcache_engine"]' ).val(),
				pgcacheEngineLabel = $container.find( 'input:checked[name="pgcache_engine"]' )
					.closest('td').next('td').text(),
				pgcacheDiffPercent = $container.find( '#test-results' )
					.data( 'pgcacheDiffPercent-' + pgcacheEngine ),
				dbcacheEngine = $container.find( 'input:checked[name="dbcache_engine"]' ).val(),
				dbcacheEngineLabel = $container.find( 'input:checked[name="dbcache_engine"]' )
					.closest('td').next('td').text(),
				objcacheEngine = $container.find( 'input:checked[name="objcache_engine"]' ).val(),
				objcacheEngineLabel = $container.find( 'input:checked[name="objcache_engine"]' )
					.closest('td').next('td').text(),
				browsercacheEnabled = $container.find( 'input:checked[name="browsercache_enable"]' ).val(),
				lazyloadEnabled = $container.find( 'input:checked#lazyload-enable' ).val();

			// Save the lazyload setting from the previous slide.
			configLazyload( ( '1' === lazyloadEnabled ? 1 : 0 ) )
			.fail( function() {
				$slide.append(
					'<div class="notice notice-error"><p><strong>' +
					W3TC_SetupGuide.config_error_msg +
					'</strong></p></div>'
				);
			});

			if ( ! jQuery( '#w3tc-wizard-step-lazyload .dashicons-yes' ).length ) {
				jQuery( '#w3tc-wizard-step-lazyload' ).append( '<span class="dashicons dashicons-yes"></span>' );
			}

			// Prevent leave page alert.
			jQuery( window ).off( 'beforeunload' );

			// Present the Setup Complete slide.
			$container.find( '#w3tc-options-menu li' ).removeClass( 'is-active' );
			$container.find( '#w3tc-options-menu li' ).last().addClass( 'is-active' );

			html = pgcacheDiffPercent !== undefined ?
				( pgcacheDiffPercent > 0 ? '+' : '' ) +
				parseFloat( pgcacheDiffPercent ).toFixed( 2 ) +
				'%' : '0.00%';

			$container.find( '#w3tc-ttfb-diff' ).html( html );

			$container.find( '#w3tc-pgcache-engine' ).html( pgcacheEngineLabel );

			$container.find( '#w3tc-dbcache-engine' ).html( dbcacheEngineLabel );

			$container.find( '#w3tc-objcache-engine' ).html( objcacheEngineLabel );

			$container.find( '#w3tc-browsercache-setting' ).html(
				browsercacheEnabled ? W3TC_SetupGuide.enabled : W3TC_SetupGuide.none
			);

			$container.find( '#w3tc-lazyload-setting' ).html(
				lazyloadEnabled ? W3TC_SetupGuide.enabled : W3TC_SetupGuide.none
			);

			if ( ! jQuery( '#test-results' ).data( 'completed' ) ) {
				jQuery.ajax({
					method: 'POST',
					url: ajaxurl,
					data: {
						_wpnonce: nonce,
						action: "w3tc_wizard_skip"
					}
				})
				.done(function () {
					$container.find( '#test-results' ).data( 'completed', true );
				});
			}

			$nextButton.closest( 'span' ).hide();
			$dashboardButton.closest( 'span' ).show();

			break;

		default:
			break;
	}
};
