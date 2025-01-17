/* global eauthDkimApi */

jQuery(($) => {
	const selectorSelect = $('[name="eauth_dkim_selector"]');

	let dkimDomain;

	const showDns = EmailAuthPlugin.instance.makeChecker(
		'dkim',
		'DKIM',
		() => `${eauthDkimApi.keys}/${selectorSelect.val()}/dns/${dkimDomain}`,
		() => {
			if (!selectorSelect.val()) {
				return {
					pass: false,
					reason: 'No DKIM selector.',
				};
			}

			if (dkimDomain === null) {
				return {
					pass: null,
					reason: 'Unknown DKIM domain. DKIM will only be applied if the domain can be figured out by WordPress.',
				};
			}
		},
		(res) => [
			EmailAuthPlugin.createCheckedDomain(res.host),
			$('<h3>').text('DNS Record'),
			$('<details>').append(
				$('<summary>').append('Show DNS Record'),
				EmailAuthPlugin.createTxtRecord(res.host, res.dns)
			),
		],
		{
			alignment: {
				getDomain: () => dkimDomain,
				type: 'DKIM',
			},
		}
	);

	new EAUTHRadioDependentListener(
		'eauth_dkim_domain',
		(val) => {
			dkimDomain = val;
			showDns();
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

	selectorSelect.on('change', showDns);
	EmailAuthPlugin.instance.addEventListener('fromdomainchange', showDns);

	async function loadKeys() {
		const keys = await (
			await EmailAuthPlugin.request(eauthDkimApi.keys)
		).json();

		const selectorValue = selectorSelect.val();

		selectorSelect.empty().append(
			$('<option value="">Disabled</option>'),
			keys.map((key) => $('<option>').text(key))
		);

		selectorSelect.val(selectorValue);
		selectorSelect.val(selectorSelect.val());
		showDns();

		$('#eauth-dkim-manager')
			.empty()
			.append(
				keys.map((selector) =>
					$('<li class="eauth-dkim-key">').append(
						selector,
						' ',
						$('<button type="button">[Download]</button>').on(
							'click',
							async () => {
								window.open(
									`${eauthDkimApi.keys}/${selector}/download?_wpnonce=${eauthCommonConfig.nonce}`
								);
							}
						),
						' ',
						$('<button type="button">[Delete]</button>').on(
							'click',
							async () => {
								if (
									!confirm(
										`Are you sure you want to delete the key with selector ${selector}?`
									)
								) {
									return;
								}

								await EmailAuthPlugin.request(
									`${eauthDkimApi.keys}/${selector}`,
									'DELETE'
								);
								await loadKeys();
							}
						)
					)
				)
			);
	}

	loadKeys();

	$('#eauth-dkim-upload').on('click', async () => {
		const selector = $('#dkim-new-name').val();

		const fileInput = $('<input type="file">');
		fileInput.click();

		fileInput.on('change', async () => {
			await EmailAuthPlugin.request(eauthDkimApi.keys, 'POST', {
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({
					name: selector,
					key: await fileInput.prop('files')[0].text(),
				}),
			});

			await loadKeys();
		});
	});

	$('#eauth-dkim-create').on('click', async () => {
		const selector = $('#dkim-new-name').val();

		await EmailAuthPlugin.request(eauthDkimApi.keys, 'POST', {
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ name: selector }),
		});

		await loadKeys();
	});
});
