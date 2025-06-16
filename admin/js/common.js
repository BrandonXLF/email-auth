class EAUTHRadioDependentListener {
	name;
	callback;
	modes;
	removeListener;

	constructor(name, callback, modes) {
		this.name = name;
		this.callback = callback;
		this.modes = modes;

		this.radioChanged();
		jQuery(`[name="${this.name}"]`).on('change', () => this.radioChanged());
	}

	radioChanged() {
		this.removeListener?.();

		const mode = jQuery(`[name="${this.name}"]:checked`).val();
		const modeData = this.modes[mode];
		const target = modeData.target?.();
		const listener = () => this.callback(modeData.value(target));

		listener();

		if (!target) {
			return;
		}

		if (target instanceof jQuery) {
			target.on(modeData.event, listener);
			this.removeListener = () => target.off(modeData.event, listener);
			return;
		}

		target.addEventListener(modeData.event, listener);
		this.removeListener = () =>
			target.removeEventListener(modeData.event, listener);
	}
}

class EAUTHChecker {
	static createCheckedDomain(domain, sourceLink, sourceName, fallbackDomain) {
		const el = jQuery('<div>');

		el.append(
			'Domain: ',
			jQuery('<span>').addClass('eauth-value').text(domain)
		);

		if (fallbackDomain) {
			el.append(
				' with fallback ',
				jQuery('<span>').addClass('eauth-value').text(fallbackDomain)
			);
		}

		el.append(
			' (from ',
			jQuery('<a>').attr('href', sourceLink).text(sourceName),
			')'
		);

		return el;
	}

	#boundSetStatus;

	constructor(
		plugin,
		headingId,
		checkType,
		getRequestUrl,
		preCheck,
		process,
		domain,
		showStatus
	) {
		this.plugin = plugin;
		this.identifier = headingId;
		this.heading = jQuery(`#${headingId}`);
		this.checkType = checkType;
		this.getRequestUrl = getRequestUrl;
		this.preCheck = preCheck;
		this.process = process;
		this.domain = domain;
		this.status = this.heading.nextUntil('.eauth-status + *').last();
		this.output = this.heading.nextUntil('.eauth-output + *').last();
		this.showStatus =
			typeof showStatus === 'function'
				? showStatus
				: this.#defaultShowStatus.bind(this, showStatus?.get);
		this.boundCheck = this.#check.bind(this);
		this.#boundSetStatus = this.setStatus.bind(this);
	}

	setStatus(statusCode, status) {
		this.status
			.empty()
			.append(EmailAuthPlugin.EMOJIS[statusCode], ' ', status);
		this.heading.attr('data-status', statusCode);
	}

	showAlignmentStatus(
		alignmentDomain,
		alignedStatus,
		alignedMessage,
		setStatusInfo
	) {
		if (this.plugin.fromDomain === alignmentDomain) {
			setStatusInfo(alignedStatus, alignedMessage);
			return;
		}

		setStatusInfo(
			'partial',
			jQuery('<span>').append(
				jQuery('<a>')
					.attr('href', this.domain.link)
					.text(this.domain.type),
				this.domain.typeHasDomain ? '' : ' domain',
				' (',
				jQuery('<span>').addClass('eauth-value').text(alignmentDomain),
				') and ',
				jQuery('<a>')
					.attr('href', '#from-address')
					.text('From Address'),
				' domain (',
				jQuery('<span>')
					.addClass('eauth-value')
					.text(this.plugin.fromDomain),
				`) do not match, so the from address domain cannot be strictly verified through ${this.checkType}.`
			)
		);
	}

	alignmentStatus(
		alignmentDomain,
		alignedStatus,
		alignedMessage,
		setStatusInfo
	) {
		if (!alignmentDomain) {
			setStatusInfo(alignedStatus, alignedMessage);
			return;
		}

		const listener = () =>
			this.showAlignmentStatus(
				alignmentDomain,
				alignedStatus,
				alignedMessage,
				setStatusInfo
			);

		listener();
		this.plugin.addEventListener('fromdomainchange', listener);

		return () =>
			this.plugin.removeEventListener('fromdomainchange', listener);
	}

	#defaultShowStatus(getCheckedDomain, res, setStatusInfo) {
		if (!res.pass) {
			setStatusInfo('error', res.reason);
			return;
		}

		if (res.pass === 'partial') {
			return this.alignmentStatus(
				getCheckedDomain(),
				'partial',
				'Configured with warnings.',
				setStatusInfo
			);
		}

		return this.alignmentStatus(
			getCheckedDomain(),
			'pass',
			'Configured.',
			setStatusInfo
		);
	}

	async #check() {
		this.status.empty();
		this.output.empty();
		this.disposable?.();
		this.requestAborter?.abort('New check started.');

		this.plugin.setResult(this.identifier, null);

		const preCheckRes = this.preCheck?.();
		if (preCheckRes) {
			this.plugin.setResult(this.identifier, preCheckRes.pass);
			const statusCode =
				preCheckRes.pass === null ? 'unknown' : preCheckRes.pass;
			this.#boundSetStatus(statusCode, preCheckRes.reason);
			return;
		}

		this.status.text(`Loading ${this.checkType} record...`);
		this.heading.attr('data-status', '');

		this.requestAborter = new AbortController();
		const raw = await EmailAuthPlugin.request(this.getRequestUrl(), 'GET', {
			signal: this.requestAborter.signal,
		});
		const res = await raw.json();

		this.plugin.setResult(this.identifier, res.pass);
		this.disposable = this.showStatus(res, this.#boundSetStatus);

		if (!this.heading.hasClass('eauth-checker-header')) {
			const currentContent = this.heading.contents();

			this.heading
				.addClass('eauth-checker-header')
				.empty()
				.append(
					jQuery('<div>').append(currentContent),
					jQuery('<button>')
						.addClass(
							'dashicons dashicons-image-rotate eauth-recheck'
						)
						.attr('type', 'button')
						.attr(
							'title',
							'Recheck. Note that DNS changes may take a few minutes to show depending on their TTL.'
						)
						.on('click', this.boundCheck)
				);
		}

		this.output
			.empty()
			.append(
				EAUTHChecker.createCheckedDomain(
					this.domain.get(res),
					this.domain.link,
					this.domain.type,
					this.domain.getFallback?.(res)
				)
			)
			.append(this.process(res));
	}
}

class EmailAuthPlugin extends EventTarget {
	static EMOJIS = {
		// Heading statuses
		pass: '✅',
		error: '❌',
		partial: '✅⚠️',
		incomplete: '✅❔',
		unknown: '❔',
		// Only for individual items
		warning: '⚠️',
	};

	static #instance;

	static get instance() {
		if (!EmailAuthPlugin.#instance) {
			EmailAuthPlugin.#instance = new EmailAuthPlugin();
		}

		return EmailAuthPlugin.#instance;
	}

	static request(url, method, options = {}) {
		if (!options.headers) {
			options.headers = {};
		}

		options.method = options.method ?? method;
		options.headers['X-WP-Nonce'] = eauthCommonConfig.nonce;

		return fetch(url, options);
	}

	static createCommentList(comments, title, headingTag = 'h3') {
		if (!comments.length) {
			return;
		}

		return jQuery(`<${headingTag}>`)
			.text(title)
			.add(
				jQuery('<ul>').append(
					comments.map((comment) =>
						jQuery('<li>').html(
							comment.level
								? `${EmailAuthPlugin.EMOJIS[comment.level]} ${comment.desc}`
								: comment.desc
						)
					)
				)
			);
	}

	static createTxtRecord(host, record) {
		return jQuery('<div>')
			.addClass('eauth-dns-record')
			.append(
				jQuery('<dt>').append(
					'TXT record for ',
					jQuery('<code>').text(host)
				),
				jQuery('<dd>').text(record)
			);
	}

	fromDomain;
	bounceDomain;
	fromAddress;
	extra = {};
	results = {};

	#getFromAddressAndDomain() {
		const input = jQuery('[name="eauth_from_address"]');
		const address = input.val() || input.attr('placeholder');
		const parts = address.split('@');
		const domain = parts[1] ?? eauthCommonConfig.domain;

		this.fromDomain = domain;
		this.dispatchEvent(new CustomEvent('fromdomainchange'));

		this.fromAddress = `${parts[0]}@${domain}`;
		this.dispatchEvent(new CustomEvent('fromaddresschange'));
	}

	domReady() {
		this.#getFromAddressAndDomain();

		jQuery('[name="eauth_from_address"]').on('change', () =>
			this.#getFromAddressAndDomain()
		);

		new EAUTHRadioDependentListener(
			'eauth_bounce_address_mode',
			(val) => {
				this.bounceDomain = val;
				this.dispatchEvent(new CustomEvent('bouncedomainchange'));
			},
			{
				'': {
					value: () => null,
				},
				custom: {
					target: () => jQuery('[name="eauth_bounce_address"]'),
					event: 'change',
					value: (target) => {
						const parts = target.val().split('@');
						return parts[1] ?? eauthCommonConfig.domain;
					},
				},
				from: {
					target: () => this,
					event: 'fromdomainchange',
					value: (target) => target.fromDomain,
				},
			}
		);
	}

	setResult(identifier, pass) {
		this.results[identifier] = pass;
		this.dispatchEvent(new CustomEvent(`${identifier}resultchange`));
	}

	makeChecker(
		headingId,
		checkType,
		getRequestUrl,
		preCheck,
		process,
		domain,
		showStatus
	) {
		return new EAUTHChecker(
			this,
			headingId,
			checkType,
			getRequestUrl,
			preCheck,
			process,
			domain,
			showStatus
		);
	}
}

jQuery(($) => {
	EmailAuthPlugin.instance.domReady();

	function setVariable(el, prefix, variable) {
		el.text(prefix).append(
			$('<span>')
				.addClass('value')
				.text(EmailAuthPlugin.instance[variable] ?? '?')
		);
	}

	$('.eauth-variable').each((_, domEl) => {
		const el = $(domEl);
		const prefix = el.data('prefix');
		const variable = el.data('variable');

		setVariable(el, prefix, variable);
		EmailAuthPlugin.instance.addEventListener(
			`${variable.toLowerCase()}change`,
			() => setVariable(el, prefix, variable)
		);
	});
});
