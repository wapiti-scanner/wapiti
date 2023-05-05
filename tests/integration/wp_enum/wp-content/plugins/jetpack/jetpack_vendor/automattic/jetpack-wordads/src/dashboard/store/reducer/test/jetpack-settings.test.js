/**
 * @jest-environment jsdom
 */
import { setJetpackSettings } from '../../actions/jetpack-settings';
import reducer from '../jetpack-settings';

describe( 'Jetpack Settings Reducer', () => {
	const initState = {
		module_active: true,
		instant_search_enabled: false,
		is_updating: false,
	};
	test( 'defaults to empty', () => {
		const state = reducer( undefined, {} );
		expect( state ).toEqual( {} );
	} );
	test( 'init set jetpackSettings', () => {
		const expected = {
			module_active: true,
			instant_search_enabled: false,
			is_toggling_instant_search: false,
			is_toggling_module: false,
		};
		const newSettings = {
			module_active: true,
			instant_search_enabled: false,
		};
		const state = reducer( undefined, setJetpackSettings( newSettings ) );
		expect( state ).toEqual( expected );
	} );
	test( 'toggle instant search', () => {
		const newSettings = {
			module_active: true,
			instant_search_enabled: true,
			is_updating: true,
		};
		const expected = {
			module_active: true,
			instant_search_enabled: true,
			is_toggling_instant_search: true,
			is_toggling_module: false,
			is_updating: true,
		};
		const state = reducer( initState, setJetpackSettings( newSettings ) );
		expect( state ).toEqual( expected );
	} );
	test( 'toggle search', () => {
		const newSettings = {
			module_active: false,
			instant_search_enabled: false,
			is_updating: true,
		};
		const expected = {
			module_active: false,
			instant_search_enabled: false,
			is_toggling_instant_search: false,
			is_toggling_module: true,
			is_updating: true,
		};
		const state = reducer( initState, setJetpackSettings( newSettings ) );
		expect( state ).toEqual( expected );
	} );
} );
