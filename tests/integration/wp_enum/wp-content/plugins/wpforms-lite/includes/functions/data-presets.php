<?php
/**
 * Helper functions to get data presets.
 *
 * @since 1.8.0
 */

/**
 * US States.
 *
 * @since 1.0.0
 *
 * @return array
 */
function wpforms_us_states() {

	$states = [
		'AL' => esc_html__( 'Alabama', 'wpforms-lite' ),
		'AK' => esc_html__( 'Alaska', 'wpforms-lite' ),
		'AZ' => esc_html__( 'Arizona', 'wpforms-lite' ),
		'AR' => esc_html__( 'Arkansas', 'wpforms-lite' ),
		'CA' => esc_html__( 'California', 'wpforms-lite' ),
		'CO' => esc_html__( 'Colorado', 'wpforms-lite' ),
		'CT' => esc_html__( 'Connecticut', 'wpforms-lite' ),
		'DE' => esc_html__( 'Delaware', 'wpforms-lite' ),
		'DC' => esc_html__( 'District of Columbia', 'wpforms-lite' ),
		'FL' => esc_html__( 'Florida', 'wpforms-lite' ),
		'GA' => esc_html_x( 'Georgia', 'US State', 'wpforms-lite' ),
		'HI' => esc_html__( 'Hawaii', 'wpforms-lite' ),
		'ID' => esc_html__( 'Idaho', 'wpforms-lite' ),
		'IL' => esc_html__( 'Illinois', 'wpforms-lite' ),
		'IN' => esc_html__( 'Indiana', 'wpforms-lite' ),
		'IA' => esc_html__( 'Iowa', 'wpforms-lite' ),
		'KS' => esc_html__( 'Kansas', 'wpforms-lite' ),
		'KY' => esc_html__( 'Kentucky', 'wpforms-lite' ),
		'LA' => esc_html__( 'Louisiana', 'wpforms-lite' ),
		'ME' => esc_html__( 'Maine', 'wpforms-lite' ),
		'MD' => esc_html__( 'Maryland', 'wpforms-lite' ),
		'MA' => esc_html__( 'Massachusetts', 'wpforms-lite' ),
		'MI' => esc_html__( 'Michigan', 'wpforms-lite' ),
		'MN' => esc_html__( 'Minnesota', 'wpforms-lite' ),
		'MS' => esc_html__( 'Mississippi', 'wpforms-lite' ),
		'MO' => esc_html__( 'Missouri', 'wpforms-lite' ),
		'MT' => esc_html__( 'Montana', 'wpforms-lite' ),
		'NE' => esc_html__( 'Nebraska', 'wpforms-lite' ),
		'NV' => esc_html__( 'Nevada', 'wpforms-lite' ),
		'NH' => esc_html__( 'New Hampshire', 'wpforms-lite' ),
		'NJ' => esc_html__( 'New Jersey', 'wpforms-lite' ),
		'NM' => esc_html__( 'New Mexico', 'wpforms-lite' ),
		'NY' => esc_html__( 'New York', 'wpforms-lite' ),
		'NC' => esc_html__( 'North Carolina', 'wpforms-lite' ),
		'ND' => esc_html__( 'North Dakota', 'wpforms-lite' ),
		'OH' => esc_html__( 'Ohio', 'wpforms-lite' ),
		'OK' => esc_html__( 'Oklahoma', 'wpforms-lite' ),
		'OR' => esc_html__( 'Oregon', 'wpforms-lite' ),
		'PA' => esc_html__( 'Pennsylvania', 'wpforms-lite' ),
		'RI' => esc_html__( 'Rhode Island', 'wpforms-lite' ),
		'SC' => esc_html__( 'South Carolina', 'wpforms-lite' ),
		'SD' => esc_html__( 'South Dakota', 'wpforms-lite' ),
		'TN' => esc_html__( 'Tennessee', 'wpforms-lite' ),
		'TX' => esc_html__( 'Texas', 'wpforms-lite' ),
		'UT' => esc_html__( 'Utah', 'wpforms-lite' ),
		'VT' => esc_html__( 'Vermont', 'wpforms-lite' ),
		'VA' => esc_html__( 'Virginia', 'wpforms-lite' ),
		'WA' => esc_html__( 'Washington', 'wpforms-lite' ),
		'WV' => esc_html__( 'West Virginia', 'wpforms-lite' ),
		'WI' => esc_html__( 'Wisconsin', 'wpforms-lite' ),
		'WY' => esc_html__( 'Wyoming', 'wpforms-lite' ),
	];

	return apply_filters( 'wpforms_us_states', $states );
}

/**
 * Countries.
 *
 * @since 1.0.0
 *
 * @return array
 */
function wpforms_countries() {

	$countries = [
		'AF' => esc_html__( 'Afghanistan', 'wpforms-lite' ),
		'AX' => esc_html__( 'Åland Islands', 'wpforms-lite' ),
		'AL' => esc_html__( 'Albania', 'wpforms-lite' ),
		'DZ' => esc_html__( 'Algeria', 'wpforms-lite' ),
		'AS' => esc_html__( 'American Samoa', 'wpforms-lite' ),
		'AD' => esc_html__( 'Andorra', 'wpforms-lite' ),
		'AO' => esc_html__( 'Angola', 'wpforms-lite' ),
		'AI' => esc_html__( 'Anguilla', 'wpforms-lite' ),
		'AQ' => esc_html__( 'Antarctica', 'wpforms-lite' ),
		'AG' => esc_html__( 'Antigua and Barbuda', 'wpforms-lite' ),
		'AR' => esc_html__( 'Argentina', 'wpforms-lite' ),
		'AM' => esc_html__( 'Armenia', 'wpforms-lite' ),
		'AW' => esc_html__( 'Aruba', 'wpforms-lite' ),
		'AU' => esc_html__( 'Australia', 'wpforms-lite' ),
		'AT' => esc_html__( 'Austria', 'wpforms-lite' ),
		'AZ' => esc_html__( 'Azerbaijan', 'wpforms-lite' ),
		'BS' => esc_html__( 'Bahamas', 'wpforms-lite' ),
		'BH' => esc_html__( 'Bahrain', 'wpforms-lite' ),
		'BD' => esc_html__( 'Bangladesh', 'wpforms-lite' ),
		'BB' => esc_html__( 'Barbados', 'wpforms-lite' ),
		'BY' => esc_html__( 'Belarus', 'wpforms-lite' ),
		'BE' => esc_html__( 'Belgium', 'wpforms-lite' ),
		'BZ' => esc_html__( 'Belize', 'wpforms-lite' ),
		'BJ' => esc_html__( 'Benin', 'wpforms-lite' ),
		'BM' => esc_html__( 'Bermuda', 'wpforms-lite' ),
		'BT' => esc_html__( 'Bhutan', 'wpforms-lite' ),
		'BO' => esc_html__( 'Bolivia (Plurinational State of)', 'wpforms-lite' ),
		'BQ' => esc_html__( 'Bonaire, Saint Eustatius and Saba', 'wpforms-lite' ),
		'BA' => esc_html__( 'Bosnia and Herzegovina', 'wpforms-lite' ),
		'BW' => esc_html__( 'Botswana', 'wpforms-lite' ),
		'BV' => esc_html__( 'Bouvet Island', 'wpforms-lite' ),
		'BR' => esc_html__( 'Brazil', 'wpforms-lite' ),
		'IO' => esc_html__( 'British Indian Ocean Territory', 'wpforms-lite' ),
		'BN' => esc_html__( 'Brunei Darussalam', 'wpforms-lite' ),
		'BG' => esc_html__( 'Bulgaria', 'wpforms-lite' ),
		'BF' => esc_html__( 'Burkina Faso', 'wpforms-lite' ),
		'BI' => esc_html__( 'Burundi', 'wpforms-lite' ),
		'CV' => esc_html__( 'Cabo Verde', 'wpforms-lite' ),
		'KH' => esc_html__( 'Cambodia', 'wpforms-lite' ),
		'CM' => esc_html__( 'Cameroon', 'wpforms-lite' ),
		'CA' => esc_html__( 'Canada', 'wpforms-lite' ),
		'KY' => esc_html__( 'Cayman Islands', 'wpforms-lite' ),
		'CF' => esc_html__( 'Central African Republic', 'wpforms-lite' ),
		'TD' => esc_html__( 'Chad', 'wpforms-lite' ),
		'CL' => esc_html__( 'Chile', 'wpforms-lite' ),
		'CN' => esc_html__( 'China', 'wpforms-lite' ),
		'CX' => esc_html__( 'Christmas Island', 'wpforms-lite' ),
		'CC' => esc_html__( 'Cocos (Keeling) Islands', 'wpforms-lite' ),
		'CO' => esc_html__( 'Colombia', 'wpforms-lite' ),
		'KM' => esc_html__( 'Comoros', 'wpforms-lite' ),
		'CG' => esc_html__( 'Congo', 'wpforms-lite' ),
		'CD' => esc_html__( 'Congo (Democratic Republic of the)', 'wpforms-lite' ),
		'CK' => esc_html__( 'Cook Islands', 'wpforms-lite' ),
		'CR' => esc_html__( 'Costa Rica', 'wpforms-lite' ),
		'CI' => esc_html__( 'Côte d\'Ivoire', 'wpforms-lite' ),
		'HR' => esc_html__( 'Croatia', 'wpforms-lite' ),
		'CU' => esc_html__( 'Cuba', 'wpforms-lite' ),
		'CW' => esc_html__( 'Curaçao', 'wpforms-lite' ),
		'CY' => esc_html__( 'Cyprus', 'wpforms-lite' ),
		'CZ' => esc_html__( 'Czech Republic', 'wpforms-lite' ),
		'DK' => esc_html__( 'Denmark', 'wpforms-lite' ),
		'DJ' => esc_html__( 'Djibouti', 'wpforms-lite' ),
		'DM' => esc_html__( 'Dominica', 'wpforms-lite' ),
		'DO' => esc_html__( 'Dominican Republic', 'wpforms-lite' ),
		'EC' => esc_html__( 'Ecuador', 'wpforms-lite' ),
		'EG' => esc_html__( 'Egypt', 'wpforms-lite' ),
		'SV' => esc_html__( 'El Salvador', 'wpforms-lite' ),
		'GQ' => esc_html__( 'Equatorial Guinea', 'wpforms-lite' ),
		'ER' => esc_html__( 'Eritrea', 'wpforms-lite' ),
		'EE' => esc_html__( 'Estonia', 'wpforms-lite' ),
		'ET' => esc_html__( 'Ethiopia', 'wpforms-lite' ),
		'FK' => esc_html__( 'Falkland Islands (Malvinas)', 'wpforms-lite' ),
		'FO' => esc_html__( 'Faroe Islands', 'wpforms-lite' ),
		'FJ' => esc_html__( 'Fiji', 'wpforms-lite' ),
		'FI' => esc_html__( 'Finland', 'wpforms-lite' ),
		'FR' => esc_html__( 'France', 'wpforms-lite' ),
		'GF' => esc_html__( 'French Guiana', 'wpforms-lite' ),
		'PF' => esc_html__( 'French Polynesia', 'wpforms-lite' ),
		'TF' => esc_html__( 'French Southern Territories', 'wpforms-lite' ),
		'GA' => esc_html__( 'Gabon', 'wpforms-lite' ),
		'GM' => esc_html__( 'Gambia', 'wpforms-lite' ),
		'GE' => esc_html_x( 'Georgia', 'Country', 'wpforms-lite' ),
		'DE' => esc_html__( 'Germany', 'wpforms-lite' ),
		'GH' => esc_html__( 'Ghana', 'wpforms-lite' ),
		'GI' => esc_html__( 'Gibraltar', 'wpforms-lite' ),
		'GR' => esc_html__( 'Greece', 'wpforms-lite' ),
		'GL' => esc_html__( 'Greenland', 'wpforms-lite' ),
		'GD' => esc_html__( 'Grenada', 'wpforms-lite' ),
		'GP' => esc_html__( 'Guadeloupe', 'wpforms-lite' ),
		'GU' => esc_html__( 'Guam', 'wpforms-lite' ),
		'GT' => esc_html__( 'Guatemala', 'wpforms-lite' ),
		'GG' => esc_html__( 'Guernsey', 'wpforms-lite' ),
		'GN' => esc_html__( 'Guinea', 'wpforms-lite' ),
		'GW' => esc_html__( 'Guinea-Bissau', 'wpforms-lite' ),
		'GY' => esc_html__( 'Guyana', 'wpforms-lite' ),
		'HT' => esc_html__( 'Haiti', 'wpforms-lite' ),
		'HM' => esc_html__( 'Heard Island and McDonald Islands', 'wpforms-lite' ),
		'HN' => esc_html__( 'Honduras', 'wpforms-lite' ),
		'HK' => esc_html__( 'Hong Kong', 'wpforms-lite' ),
		'HU' => esc_html__( 'Hungary', 'wpforms-lite' ),
		'IS' => esc_html__( 'Iceland', 'wpforms-lite' ),
		'IN' => esc_html__( 'India', 'wpforms-lite' ),
		'ID' => esc_html__( 'Indonesia', 'wpforms-lite' ),
		'IR' => esc_html__( 'Iran (Islamic Republic of)', 'wpforms-lite' ),
		'IQ' => esc_html__( 'Iraq', 'wpforms-lite' ),
		'IE' => esc_html__( 'Ireland (Republic of)', 'wpforms-lite' ),
		'IM' => esc_html__( 'Isle of Man', 'wpforms-lite' ),
		'IL' => esc_html__( 'Israel', 'wpforms-lite' ),
		'IT' => esc_html__( 'Italy', 'wpforms-lite' ),
		'JM' => esc_html__( 'Jamaica', 'wpforms-lite' ),
		'JP' => esc_html__( 'Japan', 'wpforms-lite' ),
		'JE' => esc_html__( 'Jersey', 'wpforms-lite' ),
		'JO' => esc_html__( 'Jordan', 'wpforms-lite' ),
		'KZ' => esc_html__( 'Kazakhstan', 'wpforms-lite' ),
		'KE' => esc_html__( 'Kenya', 'wpforms-lite' ),
		'KI' => esc_html__( 'Kiribati', 'wpforms-lite' ),
		'KP' => esc_html__( 'Korea (Democratic People\'s Republic of)', 'wpforms-lite' ),
		'KR' => esc_html__( 'Korea (Republic of)', 'wpforms-lite' ),
		'XK' => esc_html__( 'Kosovo', 'wpforms-lite' ),
		'KW' => esc_html__( 'Kuwait', 'wpforms-lite' ),
		'KG' => esc_html__( 'Kyrgyzstan', 'wpforms-lite' ),
		'LA' => esc_html__( 'Lao People\'s Democratic Republic', 'wpforms-lite' ),
		'LV' => esc_html__( 'Latvia', 'wpforms-lite' ),
		'LB' => esc_html__( 'Lebanon', 'wpforms-lite' ),
		'LS' => esc_html__( 'Lesotho', 'wpforms-lite' ),
		'LR' => esc_html__( 'Liberia', 'wpforms-lite' ),
		'LY' => esc_html__( 'Libya', 'wpforms-lite' ),
		'LI' => esc_html__( 'Liechtenstein', 'wpforms-lite' ),
		'LT' => esc_html__( 'Lithuania', 'wpforms-lite' ),
		'LU' => esc_html__( 'Luxembourg', 'wpforms-lite' ),
		'MO' => esc_html__( 'Macao', 'wpforms-lite' ),
		'MK' => esc_html__( 'North Macedonia (Republic of)', 'wpforms-lite' ),
		'MG' => esc_html__( 'Madagascar', 'wpforms-lite' ),
		'MW' => esc_html__( 'Malawi', 'wpforms-lite' ),
		'MY' => esc_html__( 'Malaysia', 'wpforms-lite' ),
		'MV' => esc_html__( 'Maldives', 'wpforms-lite' ),
		'ML' => esc_html__( 'Mali', 'wpforms-lite' ),
		'MT' => esc_html__( 'Malta', 'wpforms-lite' ),
		'MH' => esc_html__( 'Marshall Islands', 'wpforms-lite' ),
		'MQ' => esc_html__( 'Martinique', 'wpforms-lite' ),
		'MR' => esc_html__( 'Mauritania', 'wpforms-lite' ),
		'MU' => esc_html__( 'Mauritius', 'wpforms-lite' ),
		'YT' => esc_html__( 'Mayotte', 'wpforms-lite' ),
		'MX' => esc_html__( 'Mexico', 'wpforms-lite' ),
		'FM' => esc_html__( 'Micronesia (Federated States of)', 'wpforms-lite' ),
		'MD' => esc_html__( 'Moldova (Republic of)', 'wpforms-lite' ),
		'MC' => esc_html__( 'Monaco', 'wpforms-lite' ),
		'MN' => esc_html__( 'Mongolia', 'wpforms-lite' ),
		'ME' => esc_html__( 'Montenegro', 'wpforms-lite' ),
		'MS' => esc_html__( 'Montserrat', 'wpforms-lite' ),
		'MA' => esc_html__( 'Morocco', 'wpforms-lite' ),
		'MZ' => esc_html__( 'Mozambique', 'wpforms-lite' ),
		'MM' => esc_html__( 'Myanmar', 'wpforms-lite' ),
		'NA' => esc_html__( 'Namibia', 'wpforms-lite' ),
		'NR' => esc_html__( 'Nauru', 'wpforms-lite' ),
		'NP' => esc_html__( 'Nepal', 'wpforms-lite' ),
		'NL' => esc_html__( 'Netherlands', 'wpforms-lite' ),
		'NC' => esc_html__( 'New Caledonia', 'wpforms-lite' ),
		'NZ' => esc_html__( 'New Zealand', 'wpforms-lite' ),
		'NI' => esc_html__( 'Nicaragua', 'wpforms-lite' ),
		'NE' => esc_html__( 'Niger', 'wpforms-lite' ),
		'NG' => esc_html__( 'Nigeria', 'wpforms-lite' ),
		'NU' => esc_html__( 'Niue', 'wpforms-lite' ),
		'NF' => esc_html__( 'Norfolk Island', 'wpforms-lite' ),
		'MP' => esc_html__( 'Northern Mariana Islands', 'wpforms-lite' ),
		'NO' => esc_html__( 'Norway', 'wpforms-lite' ),
		'OM' => esc_html__( 'Oman', 'wpforms-lite' ),
		'PK' => esc_html__( 'Pakistan', 'wpforms-lite' ),
		'PW' => esc_html__( 'Palau', 'wpforms-lite' ),
		'PS' => esc_html__( 'Palestine (State of)', 'wpforms-lite' ),
		'PA' => esc_html__( 'Panama', 'wpforms-lite' ),
		'PG' => esc_html__( 'Papua New Guinea', 'wpforms-lite' ),
		'PY' => esc_html__( 'Paraguay', 'wpforms-lite' ),
		'PE' => esc_html__( 'Peru', 'wpforms-lite' ),
		'PH' => esc_html__( 'Philippines', 'wpforms-lite' ),
		'PN' => esc_html__( 'Pitcairn', 'wpforms-lite' ),
		'PL' => esc_html__( 'Poland', 'wpforms-lite' ),
		'PT' => esc_html__( 'Portugal', 'wpforms-lite' ),
		'PR' => esc_html__( 'Puerto Rico', 'wpforms-lite' ),
		'QA' => esc_html__( 'Qatar', 'wpforms-lite' ),
		'RE' => esc_html__( 'Réunion', 'wpforms-lite' ),
		'RO' => esc_html__( 'Romania', 'wpforms-lite' ),
		'RU' => esc_html__( 'Russian Federation', 'wpforms-lite' ),
		'RW' => esc_html__( 'Rwanda', 'wpforms-lite' ),
		'BL' => esc_html__( 'Saint Barthélemy', 'wpforms-lite' ),
		'SH' => esc_html__( 'Saint Helena, Ascension and Tristan da Cunha', 'wpforms-lite' ),
		'KN' => esc_html__( 'Saint Kitts and Nevis', 'wpforms-lite' ),
		'LC' => esc_html__( 'Saint Lucia', 'wpforms-lite' ),
		'MF' => esc_html__( 'Saint Martin (French part)', 'wpforms-lite' ),
		'PM' => esc_html__( 'Saint Pierre and Miquelon', 'wpforms-lite' ),
		'VC' => esc_html__( 'Saint Vincent and the Grenadines', 'wpforms-lite' ),
		'WS' => esc_html__( 'Samoa', 'wpforms-lite' ),
		'SM' => esc_html__( 'San Marino', 'wpforms-lite' ),
		'ST' => esc_html__( 'Sao Tome and Principe', 'wpforms-lite' ),
		'SA' => esc_html__( 'Saudi Arabia', 'wpforms-lite' ),
		'SN' => esc_html__( 'Senegal', 'wpforms-lite' ),
		'RS' => esc_html__( 'Serbia', 'wpforms-lite' ),
		'SC' => esc_html__( 'Seychelles', 'wpforms-lite' ),
		'SL' => esc_html__( 'Sierra Leone', 'wpforms-lite' ),
		'SG' => esc_html__( 'Singapore', 'wpforms-lite' ),
		'SX' => esc_html__( 'Sint Maarten (Dutch part)', 'wpforms-lite' ),
		'SK' => esc_html__( 'Slovakia', 'wpforms-lite' ),
		'SI' => esc_html__( 'Slovenia', 'wpforms-lite' ),
		'SB' => esc_html__( 'Solomon Islands', 'wpforms-lite' ),
		'SO' => esc_html__( 'Somalia', 'wpforms-lite' ),
		'ZA' => esc_html__( 'South Africa', 'wpforms-lite' ),
		'GS' => esc_html__( 'South Georgia and the South Sandwich Islands', 'wpforms-lite' ),
		'SS' => esc_html__( 'South Sudan', 'wpforms-lite' ),
		'ES' => esc_html__( 'Spain', 'wpforms-lite' ),
		'LK' => esc_html__( 'Sri Lanka', 'wpforms-lite' ),
		'SD' => esc_html__( 'Sudan', 'wpforms-lite' ),
		'SR' => esc_html__( 'Suriname', 'wpforms-lite' ),
		'SJ' => esc_html__( 'Svalbard and Jan Mayen', 'wpforms-lite' ),
		'SZ' => esc_html__( 'Eswatini (Kingdom of)', 'wpforms-lite' ),
		'SE' => esc_html__( 'Sweden', 'wpforms-lite' ),
		'CH' => esc_html__( 'Switzerland', 'wpforms-lite' ),
		'SY' => esc_html__( 'Syrian Arab Republic', 'wpforms-lite' ),
		'TW' => esc_html__( 'Taiwan, Republic of China', 'wpforms-lite' ),
		'TJ' => esc_html__( 'Tajikistan', 'wpforms-lite' ),
		'TZ' => esc_html__( 'Tanzania (United Republic of)', 'wpforms-lite' ),
		'TH' => esc_html__( 'Thailand', 'wpforms-lite' ),
		'TL' => esc_html__( 'Timor-Leste', 'wpforms-lite' ),
		'TG' => esc_html__( 'Togo', 'wpforms-lite' ),
		'TK' => esc_html__( 'Tokelau', 'wpforms-lite' ),
		'TO' => esc_html__( 'Tonga', 'wpforms-lite' ),
		'TT' => esc_html__( 'Trinidad and Tobago', 'wpforms-lite' ),
		'TN' => esc_html__( 'Tunisia', 'wpforms-lite' ),
		'TR' => esc_html__( 'Türkiye', 'wpforms-lite' ),
		'TM' => esc_html__( 'Turkmenistan', 'wpforms-lite' ),
		'TC' => esc_html__( 'Turks and Caicos Islands', 'wpforms-lite' ),
		'TV' => esc_html__( 'Tuvalu', 'wpforms-lite' ),
		'UG' => esc_html__( 'Uganda', 'wpforms-lite' ),
		'UA' => esc_html__( 'Ukraine', 'wpforms-lite' ),
		'AE' => esc_html__( 'United Arab Emirates', 'wpforms-lite' ),
		'GB' => esc_html__( 'United Kingdom of Great Britain and Northern Ireland', 'wpforms-lite' ),
		'US' => esc_html__( 'United States of America', 'wpforms-lite' ),
		'UM' => esc_html__( 'United States Minor Outlying Islands', 'wpforms-lite' ),
		'UY' => esc_html__( 'Uruguay', 'wpforms-lite' ),
		'UZ' => esc_html__( 'Uzbekistan', 'wpforms-lite' ),
		'VU' => esc_html__( 'Vanuatu', 'wpforms-lite' ),
		'VA' => esc_html__( 'Vatican City State', 'wpforms-lite' ),
		'VE' => esc_html__( 'Venezuela (Bolivarian Republic of)', 'wpforms-lite' ),
		'VN' => esc_html__( 'Vietnam', 'wpforms-lite' ),
		'VG' => esc_html__( 'Virgin Islands (British)', 'wpforms-lite' ),
		'VI' => esc_html__( 'Virgin Islands (U.S.)', 'wpforms-lite' ),
		'WF' => esc_html__( 'Wallis and Futuna', 'wpforms-lite' ),
		'EH' => esc_html__( 'Western Sahara', 'wpforms-lite' ),
		'YE' => esc_html__( 'Yemen', 'wpforms-lite' ),
		'ZM' => esc_html__( 'Zambia', 'wpforms-lite' ),
		'ZW' => esc_html__( 'Zimbabwe', 'wpforms-lite' ),
	];

	return apply_filters( 'wpforms_countries', $countries );
}

/**
 * Calendar Months.
 *
 * @since 1.3.7
 *
 * @return array
 */
function wpforms_months() {

	$months = [
		'Jan' => esc_html__( 'January', 'wpforms-lite' ),
		'Feb' => esc_html__( 'February', 'wpforms-lite' ),
		'Mar' => esc_html__( 'March', 'wpforms-lite' ),
		'Apr' => esc_html__( 'April', 'wpforms-lite' ),
		'May' => esc_html__( 'May', 'wpforms-lite' ),
		'Jun' => esc_html__( 'June', 'wpforms-lite' ),
		'Jul' => esc_html__( 'July', 'wpforms-lite' ),
		'Aug' => esc_html__( 'August', 'wpforms-lite' ),
		'Sep' => esc_html__( 'September', 'wpforms-lite' ),
		'Oct' => esc_html__( 'October', 'wpforms-lite' ),
		'Nov' => esc_html__( 'November', 'wpforms-lite' ),
		'Dec' => esc_html__( 'December', 'wpforms-lite' ),
	];

	return apply_filters( 'wpforms_months', $months );
}

/**
 * Calendar Days.
 *
 * @since 1.3.7
 *
 * @return array
 */
function wpforms_days() {

	$days = [
		'Sun' => esc_html__( 'Sunday', 'wpforms-lite' ),
		'Mon' => esc_html__( 'Monday', 'wpforms-lite' ),
		'Tue' => esc_html__( 'Tuesday', 'wpforms-lite' ),
		'Wed' => esc_html__( 'Wednesday', 'wpforms-lite' ),
		'Thu' => esc_html__( 'Thursday', 'wpforms-lite' ),
		'Fri' => esc_html__( 'Friday', 'wpforms-lite' ),
		'Sat' => esc_html__( 'Saturday', 'wpforms-lite' ),
	];

	return apply_filters( 'wpforms_days', $days );
}

/**
 * Return available date formats.
 *
 * @since 1.7.5
 *
 * @return array
 */
function wpforms_date_formats() {

	/**
	 * Filters available date formats.
	 *
	 * @since 1.3.0
	 *
	 * @param array $date_formats Default date formats.
	 *                            Item key is JS date character - see https://flatpickr.js.org/formatting/
	 *                            Item value is in PHP format - see http://php.net/manual/en/function.date.php.
	 */
	return (array) apply_filters(
		'wpforms_datetime_date_formats',
		[
			'm/d/Y'  => 'm/d/Y',
			'd/m/Y'  => 'd/m/Y',
			'F j, Y' => 'F j, Y',
		]
	);
}

/**
 * Return available time formats.
 *
 * @since 1.7.7
 *
 * @return array
 */
function wpforms_time_formats() {

	/**
	 * Filters available time formats.
	 *
	 * @since 1.5.9
	 *
	 * @param array $time_formats Default time formats.
	 *                            Item key is in PHP format which it used in jquery.timepicker as well,
	 *                            see http://php.net/manual/en/function.date.php.
	 */
	return (array) apply_filters(
		'wpforms_datetime_time_formats',
		[
			'g:i A' => '12 H',
			'H:i'   => '24 H',
		]
	);
}
