import { expect } from '@jest/globals';
import selectors from '../site-backup';

describe( 'siteBackupStorageSelectors', () => {
	describe( 'getStorageUsageLevel()', () => {
		it.each( [
			{
				state: {
					siteBackupStorage: {},
				},
				expected: null,
			},
			{
				state: {
					siteBackupStorage: {
						usageLevel: null,
					},
				},
				expected: null,
			},
			{
				state: {
					siteBackupStorage: {
						usageLevel: 'Full',
					},
				},
				expected: 'Full',
			},
			{
				state: {
					siteBackupStorage: {
						usageLevel: 'Normal',
					},
				},
				expected: 'Normal',
			},
		] )( 'should return expected value', ( { state, expected } ) => {
			expect( selectors.getStorageUsageLevel( state ) ).toEqual( expected );
		} );
	} );

	describe( 'getStorageAddonOfferSlug()', () => {
		it.each( [
			{
				state: {
					siteBackupStorage: {},
				},
				expected: null,
			},
			{
				state: {
					siteBackupStorage: {
						addonOfferSlug: null,
					},
				},
				expected: null,
			},
			{
				state: {
					siteBackupStorage: {
						addonOfferSlug: 'jetpack_backup_product_t1',
					},
				},
				expected: 'jetpack_backup_product_t1',
			},
			{
				state: {
					siteBackupStorage: {
						addonOfferSlug: 'jetpack_backup_product_t1',
						usageLevel: 'Full',
					},
				},
				expected: 'jetpack_backup_product_t1',
			},
		] )( 'should return expected value', ( { state, expected } ) => {
			expect( selectors.getStorageAddonOfferSlug( state ) ).toEqual( expected );
		} );
	} );
} );
