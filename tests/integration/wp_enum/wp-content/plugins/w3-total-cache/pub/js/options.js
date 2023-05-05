function w3tc_popup(url, name, width, height) {
	if (width === undefined) {
		width = 800;
	}
	if (height === undefined) {
		height = 600;
	}

	return window.open(url, name, 'width=' + width + ',height=' + height + ',status=no,toolbar=no,menubar=no,scrollbars=yes');
}

function w3tc_input_enable(input, enabled) {
	jQuery(input).each(function() {
		var me = jQuery(this);
		if (enabled) {
			me.removeAttr('disabled');
		} else {
			me.attr('disabled', 'disabled');
		}

		if (enabled) {
			me.next('[type=hidden]').remove();
		} else {
			var t = me.attr('type');
			if ((t != 'radio' && t != 'checkbox') || me.is(':checked')) {
				me.after(jQuery('<input />').attr({
					type: 'hidden',
					name: me.attr('name')
				}).val(me.val()));
			}
		}
	});
}

function w3tc_minify_js_file_clear() {
	if (!jQuery('#js_files :visible').length) {
		jQuery('#js_files_empty').show();
	} else {
		jQuery('#js_files_empty').hide();
	}
}

function w3tc_minify_css_file_clear() {
	if (!jQuery('#css_files :visible').length) {
		jQuery('#css_files_empty').show();
	} else {
		jQuery('#css_files_empty').hide();
	}
}

function w3tc_minify_js_file_add(theme, template, location, file) {
	var append = jQuery('<li><table><tr><th>&nbsp;</th><th>File URI:</th><th>Template:</th><th colspan="3">Embed Location:</th></tr><tr><td>' + (jQuery('#js_files li').length + 1) + '.</td><td><input class="js_enabled" type="text" name="js_files[' + theme + '][' + template + '][' + location + '][]" value="" size="70" \/></td><td><select class="js_file_template js_enabled"></select></td><td><select class="js_file_location js_enabled"><option value="include">Embed in &lt;head&gt;</option><option value="include-body">Embed after &lt;body&gt;</option><option value="include-footer">Embed before &lt;/body&gt;</option></select></td><td><input class="js_file_delete js_enabled button" type="button" value="Delete" /> <input class="js_file_verify js_enabled button" type="button" value="Verify URI" /></td></tr></table><\/li>');
	append.find('input:text').val(file);
	var select = append.find('.js_file_template');
	for (var i in minify_templates[theme]) {
		select.append(jQuery('<option />').val(i).html(minify_templates[theme][i]));
	}
	select.val(template);
	jQuery(append).find('.js_file_location').val(location);
	jQuery('#js_files').append(append).find('li:last input:first').focus();
	w3tc_minify_js_file_clear();
}

function w3tc_minify_css_file_add(theme, template, file) {
	var append = jQuery('<li><table><tr><th>&nbsp;</th><th>File URI:</th><th colspan="2">Template:</th></tr><tr><td>' + (jQuery('#css_files li').length + 1) + '.</td><td><input class="css_enabled" type="text" name="css_files[' + theme + '][' + template + '][include][]" value="" size="70" \/></td><td><select class="css_file_template css_enabled"></select></td><td><input class="css_file_delete css_enabled button" type="button" value="Delete" /></td><td><input class="css_file_verify css_enabled button" type="button" value="Verify URI" /></td></tr></table><\/li>');
	append.find('input:text').val(file);
	var select = append.find('.css_file_template');
	for (var i in minify_templates[theme]) {
		select.append(jQuery('<option />').val(i).html(minify_templates[theme][i]));
	}
	select.val(template);
	jQuery('#css_files').append(append).find('li:last input:first').focus();
	w3tc_minify_css_file_clear();
}

function w3tc_minify_js_theme(theme) {
	jQuery('#js_themes').val(theme);
	jQuery('#js_files :text').each(function() {
		var input = jQuery(this);
		if (input.attr('name').indexOf('js_files[' + theme + ']') != 0) {
			input.parents('li').hide();
		} else {
			input.parents('li').show();
		}
	});
	w3tc_minify_js_file_clear();
}

function w3tc_minify_css_theme(theme) {
	jQuery('#css_themes').val(theme);
	jQuery('#css_files :text').each(function() {
		var input = jQuery(this);
		if (input.attr('name').indexOf('css_files[' + theme + ']') != 0) {
			input.parents('li').hide();
		} else {
			input.parents('li').show();
		}
	});
	w3tc_minify_css_file_clear();
}

function w3tc_cdn_get_cnames() {
	var cnames = [];

	jQuery('#cdn_cnames input[type=text]').each(function() {
		var cname = jQuery(this).val();

		if (cname) {
			var match = /^\*\.(.*)$/.exec(cname);

			if (match) {
				cnames = [];
				for (var i = 1; i <= 10; i++) {
					cnames.push('cdn' + i + '.' + match[1]);
				}
				return false;
			}

			cnames.push(cname);
		}
	});

	return cnames;
}

function w3tc_cdn_cnames_assign() {
	var li = jQuery('#cdn_cnames li'), size = li.length;

	if (size > 1) {
		li.eq(0).find('.cdn_cname_delete').show();
	} else {
		li.eq(0).find('.cdn_cname_delete').hide();
	}

	jQuery(li).each(function(index) {
		var label = '';

		if (size > 1) {
			switch (index) {
				case 0:
					label = '(reserved for CSS)';
					break;

				case 1:
					label = '(reserved for JS in <head>)';
					break;

				case 2:
					label = '(reserved for JS after <body>)';
					break;

				case 3:
					label = '(reserved for JS before </body>)';
					break;
			}
		}

		jQuery(this).find('span').text(label);
	});
}

function w3tc_toggle(name, check) {
	if (check === undefined) {
		check = true;
	}

	var id = '#' + name, cls = '.' + name;

	jQuery(cls).on( 'click', function() {
		var checked = check;

		jQuery(cls).each(function() {
			var _checked = jQuery(this).is(':checked');

			if ((check && !_checked) || (!check && _checked)) {
				checked = !check;

				return false;
			}
		});

		if (checked) {
			jQuery(id).attr('checked', 'checked');
		} else {
			jQuery(id).removeAttr('checked');
		}
	});

	jQuery(id).on( 'click', function() {
		var checked = jQuery(this).is(':checked');
		jQuery(cls).each(function() {
			if (checked) {
				jQuery(this).attr('checked', 'checked');
			} else {
				jQuery(this).removeAttr('checked');
			}
		});
	});
}

function w3tc_toggle2(name, dependent_ids) {
	var id = '#' + name, dependants = '', n;
	for (n = 0; n < dependent_ids.length; n++)
		dependants += (n > 0 ? ',' : '') + '#' + dependent_ids[n];

	jQuery(dependants).on( 'click', function() {
		var total_checked = true;

		jQuery(dependants).each(function() {
			var current_checked = jQuery(this).is(':checked');

			if (!current_checked)
				total_checked = false;
		});

		if (total_checked) {
			jQuery(id).attr('checked', 'checked');
		} else {
			jQuery(id).removeAttr('checked');
		}
	});

	jQuery(id).on( 'click', function() {
		var checked = jQuery(this).is(':checked');
		jQuery(dependants).each(function() {
			if (checked) {
				jQuery(this).attr('checked', 'checked');
			} else {
				jQuery(this).removeAttr('checked');
			}
		});
	});
}

function w3tc_beforeupload_bind() {
	jQuery(window).bind('beforeunload', w3tc_beforeunload);
}

function w3tc_beforeupload_unbind() {
	jQuery(window).off('beforeunload', w3tc_beforeunload);
}

function w3tc_beforeunload() {
	return 'Navigate away from this page without saving your changes?';
}

function w3tc_starts_with(s, starts_with) {
	s = s.replace(/\n/g, '');
	s = s.replace(/\s/g, '');
	return s.substr(0, starts_with.length) == starts_with;
}

function w3tc_security_headers() {
	var directive_description =
		{
			browsercache_security_hsts_directive:
			{
				maxage: 'The time, in seconds (as defined under the "Expires Header Lifetime" box of "Media & Other Files"), that the browser should remember that this site is only to be accessed using <acronym title="HyperText Transfer Protocol over SSL">HTTPS</acronym>. This only affects the site\'s main domain.',
				maxagepre: 'The time, in seconds (as defined under the "Expires Header Lifetime" box of "Media & Other Files"), that the browser should remember that this site is only to be accessed using <acronym title="HyperText Transfer Protocol over SSL">HTTPS</acronym> with a request to be included in Chrome\'s HSTS preload list - a list of sites that are hardcoded into Chrome as being <acronym title="HyperText Transfer Protocol over SSL">https</acronym> only. This only affects the site\'s main domain.',
				maxageinc: 'The time, in seconds (as defined under the "Expires Header Lifetime" box of "Media & Other Files"), that the browser should remember that this site is only to be accessed using <acronym title="HyperText Transfer Protocol over SSL">HTTPS</acronym>. This affects the site\'s subdomains as well.',
				maxageincpre: 'The time, in seconds (as defined under the "Expires Header Lifetime" box of "Media & Other Files"), that the browser should remember that this site is only to be accessed using <acronym title="HyperText Transfer Protocol over SSL">HTTPS</acronym> with a request to be included in Chrome\'s HSTS preload list - a list of sites that are hardcoded into Chrome as being <acronym title="HyperText Transfer Protocol over SSL">https</acronym> only. This affects the site\'s subdomains as well.'
			},
			browsercache_security_xfo_directive:
			{
				same: "The page can only be displayed in a frame on the same origin as the page itself.",
				deny: "The page cannot be displayed in a frame, regardless of the site attempting to do so.",
				allow: "The page can only be displayed in a frame on the specified URL."
			},
			browsercache_security_xss_directive:
			{
				0: "Disables XSS filtering.",
				1: "Enables XSS filtering (usually default in browsers). If a cross-site scripting attack is detected, the browser will sanitize the page (remove the unsafe parts).",
				block: "Enables <acronym title='Cross-Site Scripting'>XSS</acronym> filtering. Rather than sanitizing the page, the browser will prevent rendering of the page if an attack is detected."
			},
			browsercache_security_pkp_extra:
			{
				maxage: 'The time, in seconds (as defined under the "Expires Header Lifetime" box of "Media & Other Files"), that the browser should remember that this site is only to be accessed using one of the defined keys. This only affects the site\'s main domain.',
				maxageinc: 'The time, in seconds (as defined under the "Expires Header Lifetime" box of "Media & Other Files"), that the browser should remember that this site is only to be accessed using one of the defined keys. This affects the site\'s subdomains as well.'
			},
			browsercache_security_pkp_report_only:
			{
				0: 'This instructs the browser to enforce the <acronym title="HTTP Public Key Pinning">HPKP</acronym> policy.',
				1: 'This sets up <acronym title="HTTP Public Key Pinning">HPKP</acronym> without enforcement allowing you to use pinning to test its impact without the risk of a failed connection caused by your site being unreachable or <acronym title="HTTP Public Key Pinning">HPKP</acronym> being misconfigured.'
			}
		};

	jQuery('#browsercache_security_hsts_directive,#browsercache_security_xfo_directive,#browsercache_security_xss_directive,#browsercache_security_pkp_extra,#browsercache_security_pkp_report_only').on( 'change',
	function() {
		jQuery('#' + jQuery(this).attr('id') + '_description').html('<i>' + directive_description[jQuery(this).attr('id')][jQuery(this).val()] + '</i>');
			if (jQuery(this).attr('id') == 'browsercache_security_xfo_directive') {
				if (jQuery(this).val() == 'allow') {
					jQuery('#browsercache_security_xfo_allow').show();
				}else {
					jQuery('#browsercache_security_xfo_allow').hide();
				}
			}
	});

	if(jQuery('#browsercache_security_xfo_allow').length) {
		if (jQuery('#browsercache_security_xfo_directive').val() == 'allow') {
			jQuery('#browsercache_security_xfo_allow').show();
		} else {
			jQuery('#browsercache_security_xfo_allow').hide();
		}
		jQuery('#browsercache_security_hsts_directive,#browsercache_security_xfo_directive,#browsercache_security_xss_directive,#browsercache_security_pkp_extra,#browsercache_security_pkp_report_only').on( 'change', );
	}
}

function w3tc_csp_reference() {
	W3tc_Lightbox.open({
		id: 'w3tc-overlay',
		close: '',
		width: 890,
		height: 460,
		url: ajaxurl + '?action=w3tc_ajax&_wpnonce=' + w3tc_nonce +
			'&w3tc_action=browsercache_quick_reference',
	});
	jQuery('div#overlay,.lightbox-content').on( 'click', function() {
		W3tc_Lightbox.close();
	});
}

function cdn_cf_check() {
	// Prevents JS error for non W3TC pages.
	if ( typeof w3tcData === 'undefined' ) {
		return;
	}

	var cdnEnabled = jQuery( '#cdn__enabled' ).is( ':checked' ),
		cdnEngine = jQuery( '#cdn__engine' ).find( ':selected' ).val(),
		cdnFlushManually = jQuery( '[name="cdn__flush_manually"]' ).is( ':checked' );

	// Remove any cf admin notices.
	jQuery( '.w3tc-cf-notice' ).remove();

	// General page.
	if ( ! w3tcData.cdnFlushManually && cdnEnabled && ( 'cf' === cdnEngine || 'cf2' === cdnEngine ) ) {
		// Print cf admin notice.
		jQuery( '#cdn .inside' ).prepend(
			'<div class="notice notice-warning inline w3tc-cf-notice"><p>' +
			w3tcData.cfWarning +
			'</p></div>'
		);
	}

	// CDN page.
	if ( ! cdnFlushManually && w3tcData.cdnEnabled && ( 'cf' === w3tcData.cdnEngine || 'cf2' === w3tcData.cdnEngine ) ) {
		// Show warning on the CDN page for flush manually.
		jQuery( '#cdn-flushmanually-warning' ).show();
	} else {
		// Hide warning on the CDN page for flush manually.
		jQuery( '#cdn-flushmanually-warning' ).hide();
	}
}

jQuery(function() {
	// general page
	jQuery('.w3tc_read_technical_info').on( 'click', function() {
		jQuery('.w3tc_technical_info').toggle();
	});

	jQuery('#plugin_license_key_verify').on( 'click', function() {
		jQuery('.w3tc_license_verification').html("Checking...");

		var license_key = jQuery('#plugin_license_key').val();

		if (!license_key) {
			jQuery('.w3tc_license_verification').html('Please enter an license key and try again.');
			return;
		}
		var params = {
			action: 'w3tc_verify_plugin_license_key',
			license_key: license_key
		};

		jQuery.get(ajaxurl, params, function(data) {
			if (w3tc_starts_with(data + '.', 'inactive.expired.')) {
				jQuery('.w3tc_license_verification').html('The license key has expired. Please renew it.');
			} else if (w3tc_starts_with(data + '.', 'active.')) {
				jQuery('.w3tc_license_verification').html('License key is correct.');
			} else if (w3tc_starts_with(data + '.', 'inactive.by_rooturi.activations_limit_not_reached.')) {
				jQuery('.w3tc_license_verification').html('License key is correct and can be activated now.');
			} else if (w3tc_starts_with(data + '.', 'inactive.by_rooturi.')) {
				jQuery('.w3tc_license_verification').html('License key is correct but already in use on another site. See the FAQ for how to enable Pro version in development mode.');
			} else {
				jQuery('.w3tc_license_verification').html('The license key is not valid. Please check it and try again.');
			}
		}).fail(function() {
			jQuery('.w3tc_license_verification').html('Check failed');
		});
	});

	// When CDN is enabled as "cf" or "cf2", then display a notice about possible charges.
	cdn_cf_check();
	jQuery( '#cdn__enabled' ).on( 'click', cdn_cf_check );
	jQuery( '#cdn__engine' ).on( 'change', cdn_cf_check );

	/**
	 * CDN page.
	 * When CDN is enabled as "cf" or "cf2", then display a notice about possible charges.
	 */
	 jQuery( '[name="cdn__flush_manually"]' ).on( 'click', cdn_cf_check );

	// pagecache page
	w3tc_input_enable('#pgcache_reject_roles input[type=checkbox]', jQuery('#pgcache__reject__logged_roles:checked').length);
	jQuery('#pgcache__reject__logged_roles').on('click', function () {
		w3tc_input_enable('#pgcache_reject_roles input[type=checkbox]', jQuery('#pgcache__reject__logged_roles:checked').length);
	});

	if(jQuery('#pgcache__cache__nginx_handle_xml').is('*'))
		jQuery('#pgcache__cache__nginx_handle_xml').attr('checked',jQuery('#pgcache__cache__feed').is(':checked'));

	jQuery('#pgcache__cache__feed').on( 'change', function(){
		if(jQuery('#pgcache__cache__nginx_handle_xml').is('*'))
			jQuery('#pgcache__cache__nginx_handle_xml').attr('checked',this.checked);
	});

	// browsercache page
	w3tc_toggle2('browsercache_last_modified',
		['browsercache__cssjs__last_modified', 'browsercache__html__last_modified',
			'browsercache__other__last_modified']);
	w3tc_toggle2('browsercache_expires',
		['browsercache__cssjs__expires', 'browsercache__html__expires',
			'browsercache__other__expires']);
	w3tc_toggle2('browsercache_cache_control',
		['browsercache__cssjs__cache__control', 'browsercache__html__cache__control',
			'browsercache__other__cache__control']);
	w3tc_toggle2('browsercache_etag',
		['browsercache__cssjs__etag', 'browsercache__html__etag',
			'browsercache__other__etag']);
	w3tc_toggle2('browsercache_w3tc',
		['browsercache__cssjs__w3tc', 'browsercache__html__w3tc',
			'browsercache__other__w3tc']);
	w3tc_toggle2('browsercache_compression',
		['browsercache__cssjs__compression', 'browsercache__html__compression',
			'browsercache__other__compression']);
	w3tc_toggle2('browsercache_brotli',
		['browsercache__cssjs__brotli', 'browsercache__html__brotli',
			'browsercache__other__brotli']);
	w3tc_toggle2('browsercache_replace',
		['browsercache__cssjs__replace', 'browsercache__other__replace']);
	w3tc_toggle2('browsercache_querystring',
		['browsercache__cssjs__querystring', 'browsercache__other__querystring']);
	w3tc_toggle2('browsercache_nocookies',
		['browsercache__cssjs__nocookies', 'browsercache__other__nocookies']);

	w3tc_security_headers();

	// minify page
	w3tc_input_enable('.html_enabled', jQuery('#minify__html__enable:checked').length);
	w3tc_input_enable('.js_enabled', jQuery('#minify__js__enable:checked').length);
	w3tc_input_enable('.css_enabled', jQuery('#minify__css__enable:checked').length);

	w3tc_minify_js_theme(jQuery('#js_themes').val());
	w3tc_minify_css_theme(jQuery('#css_themes').val());

	jQuery('#minify__html__enable').on( 'click', function() {
		w3tc_input_enable('.html_enabled', this.checked);
	});

	jQuery('#minify__js__enable').on( 'click', function() {
		w3tc_input_enable('.js_enabled', jQuery(this).is(':checked'));
	});

	jQuery('#minify__css__enable').on( 'click', function() {
		w3tc_input_enable('.css_enabled', jQuery(this).is(':checked'));
	});

	jQuery('.js_file_verify,.css_file_verify').on('click', function () {
		var file = jQuery(this).parents('li').find(':text').val();
		if (file == '') {
			alert('Empty URI');
		} else {
			var url = '';
			if (/^https?:\/\//.test(file)) {
				url = file;
			} else {
				url = '/' + file;
			}
			w3tc_popup(url, 'file_verify');
		}
	});

	jQuery('.js_file_template').on('change', function () {
		jQuery(this).parents('li').find(':text').attr('name', 'js_files[' + jQuery('#js_themes').val() + '][' + jQuery(this).val() + '][' + jQuery(this).parents('li').find('.js_file_location').val() + '][]');
	});

	jQuery('.css_file_template').on('change', function () {
		jQuery(this).parents('li').find(':text').attr('name', 'css_files[' + jQuery('#css_themes').val() + '][' + jQuery(this).val() + '][include][]');
	});

	jQuery('.js_file_location').on('change', function () {
		jQuery(this).parents('li').find(':text').attr('name', 'js_files[' + jQuery('#js_themes').val() + '][' + jQuery(this).parents('li').find('.js_file_template').val() + '][' + jQuery(this).val() + '][]');
	});

	jQuery('.js_file_delete').on('click', function () {
		var parent = jQuery(this).parents('li');
		if (parent.find('input[type=text]').val() == '' || confirm('Are you sure you want to remove this JS file?')) {
			parent.remove();
			w3tc_minify_js_file_clear();
			w3tc_beforeupload_bind();
		}

		return false;
	});

	jQuery('.css_file_delete').on('click', function () {
		var parent = jQuery(this).parents('li');
		if (parent.find('input[type=text]').val() == '' || confirm('Are you sure you want to remove this CSS file?')) {
			parent.remove();
			w3tc_minify_css_file_clear();
			w3tc_beforeupload_bind();
		}

		return false;
	});

	jQuery('#js_file_add').on( 'click', function() {
		w3tc_minify_js_file_add(jQuery('#js_themes').val(), 'default', 'include', '');
	});

	jQuery('#css_file_add').on( 'click', function() {
		w3tc_minify_css_file_add(jQuery('#css_themes').val(), 'default', '');
	});

	jQuery('#js_themes').on( 'change', function() {
		w3tc_minify_js_theme(jQuery(this).val());
	});

	jQuery('#css_themes').on( 'change', function() {
		w3tc_minify_css_theme(jQuery(this).val());
	});

	jQuery('#minify_form').on( 'submit', function() {
		var js = [], css = [], invalid_js = [], invalid_css = [], duplicate = false, query_js = [], query_css = [];

		jQuery('#js_files :text').each(function() {
			var v = jQuery(this).val(), n = jQuery(this).attr('name'), c = v + n, g = '';
			var match = /js_files\[([a-z0-9_\/]+)\]/.exec(n);
			if (match) {
				g = '[' + jQuery('#js_themes option[value=' + match[1] + ']').text() + '] ' + v;
			}
			if (v != '') {
				for (var i = 0; i < js.length; i++) {
					if (js[i] == c) {
						duplicate = true;
						break;
					}
				}

				js.push(c);

				var qindex = v.indexOf('?');
				if (qindex != -1) {
					if (!/^(https?:)?\/\//.test(v)) {
						query_js.push(g);
					}
					v = v.substr(0, qindex);
				} else if (!/\.js$/.test(v)) {
					invalid_js.push(g);
				}
			}
		});

		jQuery('#css_files :text').each(function() {
			var v = jQuery(this).val(), n = jQuery(this).attr('name'), c = v + n, g = '';
			var match = /css_files\[([a-z0-9_\/]+)\]/.exec(n);
			if (match) {
				g = '[' + jQuery('#css_themes option[value=' + match[1] + ']').text() + '] ' + v;
			}
			if (v != '') {
				for (var i = 0; i < css.length; i++) {
					if (css[i] == c) {
						duplicate = true;
						break;
					}
				}

				css.push(c);

				var qindex = v.indexOf('?');
				if (qindex != -1) {
					if (!/^(https?:)?\/\//.test(v)) {
						query_css.push(g);
					}
					v = v.substr(0, qindex);
				} else if (!/\.css$/.test(v)) {
					invalid_css.push(g);
				}
			}
		});

		if (jQuery('#js_enabled:checked').length) {
			if (invalid_js.length && !confirm('The following files have invalid JS file extension:\r\n\r\n' + invalid_js.join('\r\n') + '\r\n\r\nAre you confident these files contain valid JS code?')) {
				return false;
			}

			if (query_js.length) {
				alert('We recommend using the entire URI for files with query string (GET) variables. You entered:\r\n\r\n' + query_js.join('\r\n'));
				return false;
			}
		}

		if (jQuery('#css_enabled:checked').length) {
			if (invalid_css.length && !confirm('The following files have invalid CSS file extension:\r\n\r\n' + invalid_css.join('\r\n') + '\r\n\r\nAre you confident these files contain valid CSS code?')) {
				return false;
			}

			if (query_css.length) {
				alert('We recommend using the entire URI for files with query string (GET) variables. You entered:\r\n\r\n' + query_css.join('\r\n'));
				return false;
			}
		}

		if (duplicate) {
			alert('Duplicate files have been found in your minify settings, please check your settings and re-save.');
			return false;
		}

		return true;
	});

	// CDN
	jQuery('.w3tc-tab').on( 'click', function() {
		jQuery('.w3tc-tab-content').hide();
		jQuery(this.rel).show();
	});

	w3tc_input_enable('#cdn_reject_roles input[type=checkbox]', jQuery('#cdn__reject__logged_roles:checked').length);
	jQuery('#cdn__reject__logged_roles').on('click', function () {
		w3tc_input_enable('#cdn_reject_roles input[type=checkbox]', jQuery('#cdn__reject__logged_roles:checked').length);
	});

	jQuery('#cdn_export_library').on( 'click', function() {
		w3tc_popup('admin.php?page=w3tc_cdn&w3tc_cdn_export_library&_wpnonce=' + jQuery(this).metadata().nonce, 'cdn_export_library');
	});

	jQuery('#cdn_import_library').on( 'click', function() {
		w3tc_popup('admin.php?page=w3tc_cdn&w3tc_cdn_import_library&_wpnonce=' + jQuery(this).metadata().nonce, 'cdn_import_library');
	});

	jQuery('#cdn_queue').on( 'click', function() {
		w3tc_popup('admin.php?page=w3tc_cdn&w3tc_cdn_queue&_wpnonce=' + jQuery(this).metadata().nonce, 'cdn_queue');
	});

	jQuery('#cdn_rename_domain').on( 'click', function() {
		w3tc_popup('admin.php?page=w3tc_cdn&w3tc_cdn_rename_domain&_wpnonce=' + jQuery(this).metadata().nonce, 'cdn_rename_domain');
	});

	jQuery('#cdn_purge').on( 'click', function() {
		w3tc_popup('admin.php?page=w3tc_cdn&w3tc_cdn_purge&_wpnonce=' + jQuery(this).metadata().nonce, 'cdn_purge');
	});

	jQuery('.cdn_export').on( 'click', function() {
		var metadata = jQuery(this).metadata();
		w3tc_popup('admin.php?page=w3tc_cdn&w3tc_cdn_export&cdn_export_type=' + metadata.type + '&_wpnonce=' + metadata.nonce, 'cdn_export_' + metadata.type);
	});

	jQuery('#validate_cdn_key').on( 'click', function() {
	  var me = jQuery(this);
	  var metadata = me.metadata();
	  w3tc_validate_cdn_key_result(metadata.type, metadata.nonce);
	});

	jQuery('#use_poll_zone').on( 'click', function() {
	  var me = jQuery(this);
	  var metadata = me.metadata();
	  w3tc_use_poll_zone(metadata.type, metadata.nonce);
	});

	jQuery('#cdn_test').on( 'click', function() {
		var me = jQuery(this);
		var metadata = me.metadata();
		var cnames = w3tc_cdn_get_cnames();
		var params = {
			w3tc_cdn_test: 1,
			_wpnonce: metadata.nonce
		};

		switch (metadata.type) {
			case 'ftp':
				jQuery.extend(params, {
					engine: 'ftp',
					'config[host]': jQuery('#cdn_ftp_host').val(),
					'config[type]': jQuery('#cdn_ftp_type').val(),
					'config[user]': jQuery('#cdn_ftp_user').val(),
					'config[path]': jQuery('#cdn_ftp_path').val(),
					'config[pass]': jQuery('#cdn_ftp_pass').val(),
					'config[pasv]': jQuery('#cdn__ftp__pasv:checked').length,
					'config[default_keys]': jQuery('#cdn__ftp__default_keys:checked').length,
					'config[pubkey]': jQuery('#cdn_ftp_pubkey').val(),
					'config[privkey]': jQuery('#cdn_ftp_privkey').val()
				});

				if (cnames.length) {
					params['config[domain][]'] = cnames;
				}
				break;

			case 's3':
				jQuery.extend(params, {
					engine: 's3',
					'config[key]': jQuery('#cdn_s3_key').val(),
					'config[secret]': jQuery('#cdn_s3_secret').val(),
					'config[bucket]': jQuery('#cdn_s3_bucket').val(),
					'config[bucket_location]': jQuery('#cdn_s3_bucket_location').val()
				});

				if (cnames.length) {
					params['config[cname][]'] = cnames;
				}
				break;

			case 'cf':
				jQuery.extend(params, {
					engine: 'cf',
					'config[key]': jQuery('#cdn_cf_key').val(),
					'config[secret]': jQuery('#cdn_cf_secret').val(),
					'config[bucket]': jQuery('#cdn_cf_bucket').val(),
					'config[bucket_location]': jQuery('#cdn_cf_bucket_location').val(),
					'config[id]': jQuery('#cdn_cf_id').val()
				});

				if (cnames.length) {
					params['config[cname][]'] = cnames;
				}
				break;

			case 'cf2':
				jQuery.extend(params, {
					engine: 'cf2',
					'config[key]': jQuery('#cdn_cf2_key').val(),
					'config[secret]': jQuery('#cdn_cf2_secret').val(),
					'config[origin]': jQuery('#cdn_cf2_origin').val(),
					'config[id]': jQuery('#cdn_cf2_id').val()
				});

				if (cnames.length) {
					params['config[cname][]'] = cnames;
				}
				break;

			case 'rscf':
				jQuery.extend(params, {
					engine: 'rscf',
					'config[user]': jQuery('#cdn_rscf_user').val(),
					'config[key]': jQuery('#cdn_rscf_key').val(),
					'config[location]': jQuery('#cdn_rscf_location').val(),
					'config[container]': jQuery('#cdn_rscf_container').val(),
					'config[id]': jQuery('#cdn_rscf_id').val()
				});

				if (cnames.length) {
					params['config[cname][]'] = cnames;
				}
				break;

			case 'azure':
				jQuery.extend(params, {
					engine: 'azure',
					'config[user]': jQuery('#cdn_azure_user').val(),
					'config[key]': jQuery('#cdn_azure_key').val(),
					'config[container]': jQuery('#cdn_azure_container').val()
				});

				if (cnames.length) {
					params['config[cname][]'] = cnames;
				}
				break;

			case 'mirror':
				jQuery.extend(params, {
					engine: 'mirror'
				});

				if (cnames.length) {
					params['config[domain][]'] = cnames;
				}
				break;

			case 'cotendo':
				var zones = [], zones_val = jQuery('#cdn_cotendo_zones').val();

				if (zones_val) {
					zones = zones_val.split(/[\r\n,;]+/);
				}

				jQuery.extend(params, {
					engine: 'cotendo',
					'config[username]': jQuery('#cdn_cotendo_username').val(),
					'config[password]': jQuery('#cdn_cotendo_password').val()
				});

				if (zones.length) {
					params['config[zones][]'] = zones;
				}

				if (cnames.length) {
					params['config[domain][]'] = cnames;
				}
				break;
			case 'akamai':
				var emails = [], emails_val = jQuery('#cdn_akamai_email_notification').val();

				if (emails_val) {
					emails = emails_val.split(/[\r\n,;]+/);
				}

				jQuery.extend(params, {
					engine: 'akamai',
					'config[username]': jQuery('#cdn_akamai_username').val(),
					'config[password]': jQuery('#cdn_akamai_password').val(),
					'config[zone]': jQuery('#cdn_akamai_zone').val()
				});

				if (emails.length) {
					params['config[email_notification][]'] = emails;
				}

				if (cnames.length) {
					params['config[domain][]'] = cnames;
				}
				break;

			case 'edgecast':
				jQuery.extend(params, {
					engine: 'edgecast',
					'config[account]': jQuery('#cdn_edgecast_account').val(),
					'config[token]': jQuery('#cdn_edgecast_token').val()
				});

				if (cnames.length) {
					params['config[domain][]'] = cnames;
				}
				break;

			case 'att':
				jQuery.extend(params, {
					engine: 'att',
					'config[account]': jQuery('#cdn_att_account').val(),
					'config[token]': jQuery('#cdn_att_token').val()
				});

				if (cnames.length) {
					params['config[domain][]'] = cnames;
				}
				break;
			default:
				jQuery.extend(params, {
					engine: metadata.type
				});
		}

		var status = jQuery('#cdn_test_status');
		status.removeClass('w3tc-error');
		status.removeClass('w3tc-success');
		status.addClass('w3tc-process');

		var status2 = jQuery('#cdn_create_container_status');
		status2.removeClass('w3tc-error');
		status2.removeClass('w3tc-success');
		status2.html('');

		status.html('Testing...');

		jQuery.post('admin.php?page=w3tc_dashboard', params, function(data) {
			status.addClass(data.result ? 'w3tc-success' : 'w3tc-error');
			status.html(data.error);
		}, 'json').fail(function() {
			status.addClass('w3tc-error');
			status.html('Test failed');
		});
	});

	jQuery('#cdn_create_container').on('click', function () {
		var me = jQuery(this);
		var metadata = me.metadata();
		var cnames = w3tc_cdn_get_cnames();
		var container_id = null;
		var params = {
			w3tc_cdn_create_container: 1,
			_wpnonce: metadata.nonce
		};

		switch (metadata.type) {
			case 's3':
				jQuery.extend(params, {
					engine: 's3',
					'config[key]': jQuery('#cdn_s3_key').val(),
					'config[secret]': jQuery('#cdn_s3_secret').val(),
					'config[bucket]': jQuery('#cdn_s3_bucket').val(),
					'config[bucket_location]': jQuery('#cdn_s3_bucket_location').val()
				});

				if (cnames.length) {
					params['config[cname][]'] = cnames;
				}
				break;

			case 'cf':
				container_id = jQuery('#cdn_cf_id');

				jQuery.extend(params, {
					engine: 'cf',
					'config[key]': jQuery('#cdn_cf_key').val(),
					'config[secret]': jQuery('#cdn_cf_secret').val(),
					'config[bucket]': jQuery('#cdn_cf_bucket').val(),
					'config[bucket_location]': jQuery('#cdn_cf_bucket_location').val()
				});

				if (cnames.length) {
					params['config[cname][]'] = cnames;
				}
				break;

			case 'cf2':
				container_id = jQuery('#cdn_cf2_id');

				jQuery.extend(params, {
					engine: 'cf2',
					'config[key]': jQuery('#cdn_cf2_key').val(),
					'config[secret]': jQuery('#cdn_cf2_secret').val(),
					'config[origin]': jQuery('#cdn_cf2_origin').val(),
					'config[bucket_location]': jQuery('#cdn_cf2_bucket_location').val()
				});

				if (cnames.length) {
					params['config[cname][]'] = cnames;
				}
				break;

			case 'rscf':
				container_id = jQuery('#cdn_cnames input[type=text]:first');

				jQuery.extend(params, {
					engine: 'rscf',
					'config[user]': jQuery('#cdn_rscf_user').val(),
					'config[key]': jQuery('#cdn_rscf_key').val(),
					'config[location]': jQuery('#cdn_rscf_location').val(),
					'config[container]': jQuery('#cdn_rscf_container').val()
				});

				if (cnames.length) {
					params['config[cname][]'] = cnames;
				}
				break;

			case 'azure':
				jQuery.extend(params, {
					engine: 'azure',
					'config[user]': jQuery('#cdn_azure_user').val(),
					'config[key]': jQuery('#cdn_azure_key').val(),
					'config[container]': jQuery('#cdn_azure_container').val()
				});

				if (cnames.length) {
					params['config[cname][]'] = cnames;
				}
				break;
		}

		var status = jQuery('#cdn_create_container_status');
		status.removeClass('w3tc-error');
		status.removeClass('w3tc-success');
		status.addClass('w3tc-process');

		var status2 = jQuery('#cdn_test_status');
		status2.removeClass('w3tc-error');
		status2.removeClass('w3tc-success');
		status2.html('');

		status.html('Creating...');

		jQuery.post('admin.php?page=w3tc_dashboard', params, function(data) {
			status.addClass(data.result ? 'w3tc-success' : 'w3tc-error');
			status.html(data.error);

			if (container_id && container_id.length && data.container_id) {
				container_id.val(data.container_id);
			}
		}, 'json').fail(function() {
			status.addClass('w3tc-error');
			status.html('failed');
		});
	});

	jQuery('#memcached_test').on( 'click', function() {
		var status = jQuery('#memcached_test_status');
		status.removeClass('w3tc-error');
		status.removeClass('w3tc-success');
		status.addClass('w3tc-process');
		status.html('Testing...');
		jQuery.post('admin.php?page=w3tc_dashboard', {
			w3tc_test_memcached: 1,
			servers: jQuery('#memcached_servers').val(),
			_wpnonce: jQuery(this).metadata().nonce
		}, function(data) {
			status.addClass(data.result ? 'w3tc-success' : 'w3tc-error');
			status.html(data.error);
		}, 'json')
		.fail(function() {
			status.addClass('w3tc-error');
			status.html('Request failed');
		});
	});

	jQuery('.w3tc_common_redis_test').on( 'click', function() {
		var status = jQuery('.w3tc_common_redis_test_result');
		status.removeClass('w3tc-error');
		status.removeClass('w3tc-success');
		status.addClass('w3tc-process');
		status.html('Testing...');
		jQuery.post('admin.php?page=w3tc_dashboard', {
			w3tc_test_redis: 1,
			servers: jQuery('#redis_servers').val(),
			verify_tls_certificates: jQuery('[id$=__redis__verify_tls_certificates]').is(':checked'),
			dbid : jQuery('#redis_dbid').val(),
			password : jQuery('#redis_password').val(),
			_wpnonce: jQuery(this).metadata().nonce
		}, function(data) {
			status.addClass(data.result ? 'w3tc-success' : 'w3tc-error');
			status.html(data.error);
		}, 'json')
		.fail(function() {
			status.addClass('w3tc-error');
			status.html('Request failed');
		});
	});

	jQuery('.minifier_test').on( 'click', function() {
		var me = jQuery(this);
		var metadata = me.metadata();
		var params = {
			w3tc_test_minifier: 1,
			_wpnonce: metadata.nonce
		};

		switch (metadata.type) {
			case 'yuijs':
				jQuery.extend(params, {
					engine: 'yuijs',
					path_java: jQuery('#minify__yuijs__path__java').val(),
					path_jar: jQuery('#minify__yuijs__path__jar').val()
				});
				break;

			case 'yuicss':
				jQuery.extend(params, {
					engine: 'yuicss',
					path_java: jQuery('#minify__yuicss__path__java').val(),
					path_jar: jQuery('#minify__yuicss__path__jar').val()
				});
				break;

			case 'ccjs':
				jQuery.extend(params, {
					engine: 'ccjs',
					path_java: jQuery('#minify__ccjs__path__java').val(),
					path_jar: jQuery('#minify__ccjs__path__jar').val()
				});
				break;
			case 'googleccjs':
				jQuery.extend(params, {
					engine: 'googleccjs'
				});
				break;
		}

		var status = me.next();
		status.removeClass('w3tc-error');
		status.removeClass('w3tc-success');
		status.addClass('w3tc-process');
		status.html('Testing...');

		jQuery.post('admin.php?page=w3tc_dashboard', params, function(data) {
			status.addClass(data.result ? 'w3tc-success' : 'w3tc-error');
			status.html(data.error);
		}, 'json');
	});

	// CDN cnames
	jQuery('body').on('click', '#cdn_cname_add', function() {
		jQuery('#cdn_cnames').append('<li><input type="text" name="cdn_cnames[]" value="" size="60" /> <input class="button cdn_cname_delete" type="button" value="Delete" /> <span></span></li>');
		w3tc_cdn_cnames_assign();
		jQuery(this).trigger("size_change");
	});

	jQuery('.cdn_cname_delete').on('click', function () {
		var p = jQuery(this).parent();
		if (p.find('input[type=text]').val() == '' || confirm('Are you sure you want to remove this CNAME?')) {
			p.remove();
			w3tc_cdn_cnames_assign();
			w3tc_beforeupload_bind();
		}
	});

	jQuery('#cdn_form').on( 'submit', function() {
		var cnames = [], ret = true;

		jQuery('#cdn_cnames input[type=text]').each(function() {
			var cname = jQuery(this).val();

			if (cname) {
				if (jQuery.inArray(cname, cnames) != -1) {
					alert('CNAME "' + cname + '" already exists.');
					ret = false;

					return false;
				} else {
					cnames.push(cname);
				}
			}
		});

		return ret;
	});

	// add sortable
	if (jQuery.ui && jQuery.ui.sortable) {
		jQuery('#js_files,#css_files').sortable({
			axis: 'y',
			stop: function() {
				jQuery(this).find('li').each(function(index) {
					jQuery(this).find('td:eq(0)').html((index + 1) + '.');
				});
			}
		});

		jQuery('#cdn_cnames').sortable({
			axis: 'y',
			stop: w3tc_cdn_cnames_assign
		});

		jQuery('#mobile_groups').sortable({
			axis: 'y',
			stop: function() {
				jQuery('#mobile_groups').find('.mobile_group_number').each(function(index) {
					jQuery(this).html((index + 1) + '.');
				});
			}
		});

		jQuery('#referrer_groups').sortable({
			axis: 'y',
			stop: function() {
				jQuery('#referrer_groups').find('.referrer_group_number').each(function(index) {
					jQuery(this).html((index + 1) + '.');
				});
			}
		});
	}

	// show hide rules
	jQuery('.w3tc-show-rules').on( 'click', function() {
		var btn = jQuery(this), rules = btn.parent().find('.w3tc-rules');

		if (rules.is(':visible')) {
			rules.css('display', 'none');
			btn.val('view code');
		} else {
			rules.css('display', 'block');
			btn.val('hide code');
		}
	});


	// show hide missing files
	jQuery('.w3tc-show-required-changes').on( 'click', function() {
		var btn = jQuery(this), rules = jQuery('.w3tc-required-changes');

		if (rules.is(':visible')) {
			rules.css('display', 'none');
			btn.val('View required changes');
		} else {
			rules.css('display', 'block');
			btn.val('Hide required changes');
		}
	});

	// show hide missing files
	jQuery('.w3tc-show-ftp-form').on( 'click', function() {
		var btn = jQuery(this), rules = jQuery('.w3tc-ftp-form');

		if (rules.is(':visible')) {
			rules.css('display', 'none');
			btn.val('Update via FTP');
		} else {
			rules.css('display', 'block');
			btn.val('Cancel FTP Update');
		}
	});

	// show hide missing files
	jQuery('.w3tc-show-technical-info').on( 'click', function() {
		var btn = jQuery(this), info = jQuery('.w3tc-technical-info');

		if (info.is(':visible')) {
			info.css('display', 'none');
			btn.val('Technical Information');
		} else {
			info.css('display', 'block');
			btn.val('Hide technical information');
		}
	});

	// add ignore class to the ftp form elements
	jQuery('#ftp_upload_form').find('input').each(function() {
		jQuery(this).addClass('w3tc-ignore-change');
	});

	// toggle hiddent content
	jQuery('.w3tc_link_more').on( 'click', function() {
		var target_class = jQuery(this).metadata().for_class;
		jQuery('.' + target_class).slideToggle();
	});

	// check for unsaved changes
	jQuery('#w3tc input,#w3tc select,#w3tc textarea').on('change', function () {
		var ignore = false;
		jQuery(this).parents().addBack().each(function() {
			if (jQuery(this).hasClass('w3tc-ignore-change') || jQuery(this).hasClass('lightbox')) {
				ignore = true;
				return false;
			}
		});

		if (!ignore) {
			w3tc_beforeupload_bind();
		}
	});

	jQuery('body').on('click', '.w3tc-button-save', w3tc_beforeupload_unbind);


	jQuery('.contextual-help-tabs ul li a').on( 'click', function() {
		var id = jQuery(this).attr('aria-controls');
		var i = jQuery('#' + id + ' .w3tchelp_content');
		w3tc_load_faq_section(i);
	});

	jQuery('#contextual-help-link').on( 'click', function() {
		var i = jQuery('.w3tchelp_content').first();
		w3tc_load_faq_section(i);
	});

	var w3tchelp_loaded = {};
	function w3tc_load_faq_section(i) {
		var section = i.data('section');

		if (w3tchelp_loaded[section])
			return;

		i.html('<div class="w3tchelp_loading_outer">' +
			'<div class="w3tc-loading w3tchelp_loading_inner"></div></div>');

		w3tchelp_loaded[section] = true;

		jQuery.getJSON(ajaxurl, {
			action: 'w3tc_ajax',
			_wpnonce: w3tc_nonce[0],
			w3tc_action: 'faq',
			section: section
		}, function(data) {
			i.html(data.content)
		}).fail(function() {
			i.html('Failed to obtain data');
		});
	}

	// extensions page
	jQuery('.w3tc_extensions_manage_input_checkall').on( 'click', function(v) {
		var c = jQuery(this).is(':checked');

		jQuery('.w3tc_extensions_manage_input_checkall').prop('checked', c);
		jQuery('.w3tc_extensions_input_active').each(function(index) {
			if (!jQuery(this).is(':disabled'))
				jQuery(this).prop('checked', c);
		});
	});

	// gopro block
	jQuery('.w3tc-gopro-more').on( 'click', function(e) {
		e.preventDefault();
		if (!jQuery(this).data('expanded')) {
			jQuery(this).data('expanded', '1');
			jQuery(this).html('Show Less <span class="dashicons dashicons-arrow-up-alt2"></span>');
			jQuery(this).parent().find('.w3tc-gopro-description').css('max-height', '300px');
		} else {
			jQuery(this).data('expanded', '');
			jQuery(this).html('Show More <span class="dashicons dashicons-arrow-down-alt2"></span>');
			jQuery(this).parent().find('.w3tc-gopro-description').css('max-height', '');
		}

		if (window.w3tc_ga) {
			w3tc_ga('send', 'event', 'anchor', 'click',
				jQuery(this).data('href'));
		}

	});

	// google analytics events
	if (typeof w3tc_ga != 'undefined') {
		jQuery('.w3tc_error').each(function() {
			var id = jQuery(this).attr('id');
			var text = jQuery(this).text();
			if (id && window.w3tc_ga)
				w3tc_ga('send', 'event', 'w3tc_error', id, text);
		});
		jQuery('.w3tc_note').each(function() {
			var id = jQuery(this).attr('id');
			var text = jQuery(this).text();
			if (id && window.w3tc_ga)
				w3tc_ga('send', 'event', 'w3tc_note', id, text);
		});

		jQuery('body').on('click', 'a', function() {
			var url = jQuery(this).attr('href');
			if (url && window.w3tc_ga)
				w3tc_ga('send', 'event', 'anchor', 'click', url, {useBeacon: true});
		});

		jQuery('body').on('click', 'input[type="button"]', function() {
			var name = jQuery(this).attr('name');
			if (name && window.w3tc_ga)
				w3tc_ga('send', 'event', 'button', 'click', name, {useBeacon: true});
		});
		jQuery('body').on('click', 'input[type="submit"]', function() {
			var name = jQuery(this).attr('name');
			var id = jQuery(this).attr('id');
			if (!id)
				id = name;

			if (name && window.w3tc_ga)
				w3tc_ga('send', 'event', 'button', id, name, {useBeacon: true});
		});

		jQuery('body').on('click', 'input[type="checkbox"]', function() {
			var name = jQuery(this).attr('name');
			var action = jQuery(this).is(':checked') ? 'check' : 'uncheck';

			if (name && window.w3tc_ga)
				w3tc_ga('send', 'event', 'checkbox', action, name);
		});

		jQuery('body').on('change', 'select', function() {
			var name = jQuery(this).attr('name');
			var value = jQuery(this).val();

			if (name && value && window.w3tc_ga)
				w3tc_ga('send', 'event', 'select', value, name);
		});
	}
});
