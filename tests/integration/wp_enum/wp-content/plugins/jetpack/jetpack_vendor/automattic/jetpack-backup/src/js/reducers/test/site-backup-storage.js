import { expect } from '@jest/globals';
import { SITE_BACKUP_STORAGE_SET } from '../../actions/types';
import siteBackupStorage from '../site-backup-storage';

describe( 'reducer', () => {
	const fixtures = {
		initialState: {
			usageLevel: null,
			addonOfferSlug: null,
		},
	};

	describe( 'siteBackupStorage', () => {
		it.each( [
			{
				state: undefined,
				action: {},
				expected: fixtures.initialState,
			},
			{
				state: fixtures.initialState,
				action: {
					type: SITE_BACKUP_STORAGE_SET,
				},
				expected: fixtures.initialState,
			},
			{
				state: fixtures.initialState,
				action: {
					type: SITE_BACKUP_STORAGE_SET,
					usageLevel: 'Full',
				},
				expected: {
					usageLevel: 'Full',
					addonOfferSlug: null,
				},
			},
			{
				state: {
					usageLevel: 'Full',
					addonOfferSlug: 'jetpack_backup_product_t1',
				},
				action: {
					type: SITE_BACKUP_STORAGE_SET,
					usageLevel: 'Normal',
				},
				expected: {
					usageLevel: 'Normal',
					addonOfferSlug: 'jetpack_backup_product_t1',
				},
			},
		] )( 'should return expected state', ( { state, action, expected } ) => {
			expect( siteBackupStorage( state, action ) ).toEqual( expected );
		} );
	} );
} );
