import { expect } from '@jest/globals';
import selectors from '../site-backup';

describe( 'siteBackupSizeSelectors', () => {
	const fixtures = {
		emptyObject: {
			siteBackupSize: {},
		},
		initialState: {
			siteBackupSize: {
				isFetching: false,
				loaded: false,
				size: null,
				minDaysOfBackupsAllowed: null,
				daysOfBackupsAllowed: null,
				daysOfBackupsSaved: null,
				retentionDays: null,
			},
		},
		fetchingState: {
			siteBackupSize: {
				isFetching: true,
				loaded: false,
				size: null,
				minDaysOfBackupsAllowed: null,
				daysOfBackupsAllowed: null,
				daysOfBackupsSaved: null,
				retentionDays: null,
			},
		},
		failedState: {
			siteBackupSize: {
				isFetching: false,
				loaded: false,
				size: null,
				minDaysOfBackupsAllowed: null,
				daysOfBackupsAllowed: null,
				daysOfBackupsSaved: null,
				retentionDays: null,
			},
		},
		successState: {
			siteBackupSize: {
				isFetching: false,
				loaded: true,
				size: 10737418240,
				minDaysOfBackupsAllowed: 7,
				daysOfBackupsAllowed: 30,
				daysOfBackupsSaved: 24,
				retentionDays: 7,
			},
		},
	};

	describe( 'isFetchingBackupSize()', () => {
		it.each( [
			{
				state: fixtures.emptyObject,
				expected: null,
			},
			{
				state: fixtures.initialState,
				expected: false,
			},
			{
				state: fixtures.fetchingState,
				expected: true,
			},
			{
				state: fixtures.failedState,
				expected: false,
			},
			{
				state: fixtures.successState,
				expected: false,
			},
		] )(
			'should return isFetching bool value if passed, null otherwise',
			( { state, expected } ) => {
				const output = selectors.isFetchingBackupSize( state );
				expect( output ).toBe( expected );
			}
		);
	} );

	describe( 'getBackupSize()', () => {
		it.each( [
			{
				state: fixtures.emptyObject,
				expected: null,
			},
			{
				state: fixtures.initialState,
				expected: null,
			},
			{
				state: fixtures.fetchingState,
				expected: null,
			},
			{
				state: fixtures.failedState,
				expected: null,
			},
			{
				state: fixtures.successState,
				expected: 10737418240,
			},
		] )( 'should return size value if passed, null otherwise', ( { state, expected } ) => {
			const output = selectors.getBackupSize( state );
			expect( output ).toBe( expected );
		} );
	} );

	describe( 'getMinDaysOfBackupsAllowed()', () => {
		it.each( [
			{
				state: fixtures.emptyObject,
				expected: null,
			},
			{
				state: fixtures.initialState,
				expected: null,
			},
			{
				state: fixtures.fetchingState,
				expected: null,
			},
			{
				state: fixtures.failedState,
				expected: null,
			},
			{
				state: fixtures.successState,
				expected: 7,
			},
		] )(
			'should return minDaysOfBackupsAllowed value if passed, null otherwise',
			( { state, expected } ) => {
				const output = selectors.getMinDaysOfBackupsAllowed( state );
				expect( output ).toBe( expected );
			}
		);
	} );

	describe( 'getDaysOfBackupsAllowed()', () => {
		it.each( [
			{
				state: fixtures.emptyObject,
				expected: null,
			},
			{
				state: fixtures.initialState,
				expected: null,
			},
			{
				state: fixtures.fetchingState,
				expected: null,
			},
			{
				state: fixtures.failedState,
				expected: null,
			},
			{
				state: fixtures.successState,
				expected: 30,
			},
		] )(
			'should return daysOfBackupsAllowed value if passed, null otherwise',
			( { state, expected } ) => {
				const output = selectors.getDaysOfBackupsAllowed( state );
				expect( output ).toBe( expected );
			}
		);
	} );

	describe( 'getDaysOfBackupsSaved()', () => {
		it.each( [
			{
				state: fixtures.emptyObject,
				expected: null,
			},
			{
				state: fixtures.initialState,
				expected: null,
			},
			{
				state: fixtures.fetchingState,
				expected: null,
			},
			{
				state: fixtures.failedState,
				expected: null,
			},
			{
				state: fixtures.successState,
				expected: 24,
			},
		] )(
			'should return getDaysOfBackupsSaved value if passed, null otherwise',
			( { state, expected } ) => {
				const output = selectors.getDaysOfBackupsSaved( state );
				expect( output ).toBe( expected );
			}
		);
	} );

	describe( 'getBackupRetentionDays()', () => {
		it.each( [
			{
				state: fixtures.emptyObject,
				expected: null,
			},
			{
				state: fixtures.initialState,
				expected: null,
			},
			{
				state: fixtures.fetchingState,
				expected: null,
			},
			{
				state: fixtures.failedState,
				expected: null,
			},
			{
				state: fixtures.successState,
				expected: 7,
			},
		] )(
			'should return getBackupRetentionDays value if passed, null otherwise',
			( { state, expected } ) => {
				const output = selectors.getBackupRetentionDays( state );
				expect( output ).toBe( expected );
			}
		);
	} );
} );
