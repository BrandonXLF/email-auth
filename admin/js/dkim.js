/* global eauthDkimApi */

const { __, sprintf } = wp.i18n;

jQuery(($) => {
	const selectorSelect = $('[name="eauth_dkim_selector"]');

	// Per RFC 6367 3.1 and RFC 5321 4.1.2.
	const compliantSelectorPattern =
		/^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/;

	const checker = EmailAuthPlugin.instance.makeChecker(
		'dkim',
		'DKIM',
		() =>
			`${eauthDkimApi.keys}/${selectorSelect.val()}/dns/${EmailAuthPlugin.instance.extra.dkimDomain}`,
		() => {
			if (!selectorSelect.val()) {
				return {
					pass: false,
					reason: __('No DKIM selector.', 'email-auth'),
				};
			}

			if (EmailAuthPlugin.instance.extra.dkimDomain === null) {
				return {
					pass: null,
					reason: __(
						'Unknown DKIM domain. DKIM will only be applied if the domain can be figured out by WordPress.',
						'email-auth'
					),
				};
			}
		},
		(res) => [
			EmailAuthPlugin.createCommentList(
				res.warnings.map((desc) => ({
					level: 'warning',
					desc,
				})),
				__('Warnings', 'email-auth')
			),
			res.dns && $('<h3>').text(__('Generated DNS Record', 'email-auth')),
			res.dns &&
				$('<details>').append(
					$('<summary>')
						.addClass('button-link')
						.append(__('Show Generated DNS Record', 'email-auth')),
					EmailAuthPlugin.createTxtRecord(res.host, res.dns)
				),
		],
		{
			get: (res) => res.host,
			type: __('DKIM Domain', 'email-auth'),
			link: '#dkim-domain',
			typeHasDomain: true,
		},
		{
			get: () => EmailAuthPlugin.instance.extra.dkimDomain,
		}
	);

	new EAUTHRadioDependentListener(
		'eauth_dkim_domain',
		(val) => {
			EmailAuthPlugin.instance.extra.dkimDomain = val;
			EmailAuthPlugin.instance.dispatchEvent(
				new CustomEvent('dkimdomainchange')
			);
		},
		{
			wp: {
				value: () => eauthCommonConfig.domain,
			},
			from: {
				target: () => EmailAuthPlugin.instance,
				event: 'fromdomainchange',
				value: (target) => target.fromDomain,
			},
			bounce: {
				target: () => EmailAuthPlugin.instance,
				event: 'bouncedomainchange',
				value: (target) => target.bounceDomain,
			},
			custom: {
				target: () => $('[name="eauth_dkim_domain_custom"]'),
				event: 'change',
				value: (target) => target.val(),
			},
		}
	);

	checker.boundCheck();
	EmailAuthPlugin.instance.addEventListener(
		'dkimdomainchange',
		checker.boundCheck
	);
	selectorSelect.on('change', checker.boundCheck);

	function clearSubmissionError() {
		$('#eauth-dkim-manager-error').empty();
	}

	async function loadKeys() {
		$('#eauth-dkim-manager').text(__('Loading keys…', 'email-auth'));

		const keys = await (
			await EmailAuthPlugin.request(eauthDkimApi.keys)
		).json();

		const selectorValue = selectorSelect.val();

		selectorSelect.empty().append(
			$('<option value="">').text(__('Disabled', 'email-auth')),
			keys.map((key) => $('<option>').text(key))
		);

		selectorSelect.val(selectorValue);
		selectorSelect.val(selectorSelect.val());

		if (selectorSelect.val() !== selectorValue) {
			checker.boundCheck();
		}

		$('#eauth-dkim-manager')
			.empty()
			.append(
				keys.map((selector) =>
					$('<li class="eauth-dkim-key">').append(
						selector,
						' ',
						$('<button type="button">')
							.text(__('Download', 'email-auth'))
							.on('click', async () => {
								window.open(
									`${eauthDkimApi.keys}/${selector}/download?_wpnonce=${eauthCommonConfig.nonce}`
								);
							}),
						' ',
						$('<button type="button">')
							.text(__('Delete', 'email-auth'))
							.on('click', async () => {
								if (
									!confirm(
										sprintf(
											/* translators: %s: DKIM selector name */
											__(
												'Are you sure you want to delete the key with selector %s?',
												'email-auth'
											),
											selector
										)
									)
								) {
									return;
								}

								clearSubmissionError();

								await EmailAuthPlugin.request(
									`${eauthDkimApi.keys}/${selector}`,
									'DELETE'
								);

								await loadKeys();
							})
					)
				)
			);
	}

	loadKeys();

	async function postKey(selector, body) {
		clearSubmissionError();

		if (!compliantSelectorPattern.test(selector)) {
			const ignoreNonCompliant = confirm(
				sprintf(
					/* translators: %s: DKIM selector name */
					__(
						'Selector "%s" is non-standard. A valid selector must contain ASCII letters and numbers with optional hyphens in-between. Dots can be used to separate subdomains. Would you like to continue anyway?',
						'email-auth'
					),
					selector
				)
			);

			if (!ignoreNonCompliant) {
				return;
			}
		}

		const res = await EmailAuthPlugin.request(
			`${eauthDkimApi.keys}/${selector}`,
			'POST',
			{
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify(body) ?? '{}',
			}
		);

		if (!res.ok) {
			const json = await res.json();
			$('#eauth-dkim-manager-error').text(json.error);
		}

		await loadKeys();
	}

	$('#eauth-dkim-upload').on('click', async () => {
		const selector = $('#dkim-new-name').val();

		const fileInput = $('<input type="file">');
		fileInput.click();

		fileInput.on('change', async () =>
			postKey(selector, {
				key: await fileInput.prop('files')[0].text(),
			})
		);
	});

	$('#eauth-dkim-create').on('click', async () => {
		const selector = $('#dkim-new-name').val();
		postKey(selector);
	});
});
