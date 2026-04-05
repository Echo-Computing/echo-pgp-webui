"""
pgp_mobile/main.py — PGP Vault mobile app entry point

Two modes:
- Connect page: enter server URL + auth token
- Main app: Compose, Inbox, Sent, Keys tabs
"""

import flet as ft
from flet import Page

# ─── State ────────────────────────────────────────────────────────────────────

_server_url = ft.Ref[str]()
_token = ft.Ref[str]()
_client = ft.Ref[object]()

# ─── Helpers ─────────────────────────────────────────────────────────────────

def get_client():
    import lib.api_client as api_client_module
    url = _server_url.current or ''
    token = _token.current or ''
    if not url or not token:
        return None
    return api_client_module.PGPVaultClient(url, token, verify_tls=True)

# ─── Page: Connect ─────────────────────────────────────────────────────────────

def connect_page(page: Page):
    """Connection setup page — shown on first launch."""
    status_ref = ft.Ref[ft.Text]()
    url_field = ft.Ref[ft.TextField]()
    token_field = ft.Ref[ft.TextField]()
    connect_btn = ft.Ref[ft.ElevatedButton]()

    def do_connect(e):
        url = url_field.current.value or ''
        token = token_field.current.value or ''
        if not url or not token:
            status_ref.current.value = 'URL and token are required'
            status_ref.current.color = ft.colors.ERROR
            page.update()
            return

        connect_btn.current.disabled = True
        status_ref.current.value = 'Connecting...'
        page.update()

        client = __import__('lib.api_client', fromlist=['PGVaultClient']).PGVaultClient(url, token, verify_tls=True)
        ok, msg = client.test_connection()
        if ok:
            _server_url.current = url
            _token.current = token
            client.close()
            main_app(page)
        else:
            status_ref.current.value = f'Connection failed: {msg}'
            status_ref.current.color = ft.colors.ERROR
            connect_btn.current.disabled = False
            page.update()

    page.title = 'PGP Vault — Connect'
    page.padding = 20
    page.add(
        ft.Container(height=40),
        ft.Icon(ft.icons.LOCK, size=64, color=ft.colors.PRIMARY),
        ft.Container(height=10),
        ft.Text('PGP Vault', size=28, weight=ft.FontWeight.BOLD),
        ft.Text('Connect to your desktop server', size=14, color=ft.colors.GREY),
        ft.Container(height=30),
        ft.TextField(
            ref=url_field,
            label='Server URL',
            hint_text='https://192.168.50.239:8765',
            prefix_icon=ft.icons.LINK,
            keyboard_type=ft.KeyboardType.URL,
            autofocus=True,
        ),
        ft.Container(height=15),
        ft.TextField(
            ref=token_field,
            label='Auth Token',
            hint_text='From desktop Settings page',
            prefix_icon=ft.icons.KEY,
            password=True,
            can_reveal_password=True,
        ),
        ft.Container(height=10),
        ft.Text(ref=status_ref, size=13),
        ft.Container(height=15),
        ft.ElevatedButton(
            ref=connect_btn,
            text='Connect',
            icon=ft.icons.LOGIN,
            on_click=do_connect,
            width=page.width or 350,
        ),
        ft.Container(height=20),
        ft.Text(
            'Find the auth token on your desktop server:\n'
            'Settings → Mobile API → copy the token',
            size=11, color=ft.colors.GREY, text_align=ft.TextAlign.CENTER,
        ),
    )

# ─── Page: Compose ─────────────────────────────────────────────────────────────

def compose_page(page: Page):
    """Compose and send encrypted messages."""
    recipient_field = ft.Ref[ft.Dropdown]()
    subject_field = ft.Ref[ft.TextField]()
    message_field = ft.Ref[ft.TextField]()
    status_ref = ft.Ref[ft.Text]()
    send_btn = ft.Ref[ft.ElevatedButton]()

    # Fetch recipients from server
    recipients = ['coda@vault.local', 'echo@vault.local']
    try:
        client = get_client()
        if client:
            msgs = client.list_messages(limit=200)
            seen = set()
            for m in msgs:
                r = m.get('recipient', '')
                s = m.get('sender', '')
                if r and r not in seen:
                    recipients.append(r)
                    seen.add(r)
                if s and s not in seen:
                    recipients.append(s)
                    seen.add(s)
            client.close()
    except Exception:
        pass

    def do_send(e):
        recipient = recipient_field.current.value or ''
        subject = subject_field.current.value or ''
        message = message_field.current.value or ''
        if not recipient or not message:
            status_ref.current.value = 'Recipient and message are required'
            status_ref.current.color = ft.colors.ERROR
            page.update()
            return

        send_btn.current.disabled = True
        status_ref.current.value = 'Encrypting and sending...'
        page.update()

        try:
            client = get_client()
            result = client.send_message(recipient, message, subject)
            status_ref.current.value = f'Sent! ID: {result.get("id")}'
            status_ref.current.color = ft.colors.GREEN
            subject_field.current.value = ''
            message_field.current.value = ''
        except Exception as ex:
            status_ref.current.value = f'Error: {ex}'
            status_ref.current.color = ft.colors.ERROR
        finally:
            send_btn.current.disabled = False
            page.update()

    page.title = 'Compose'
    page.scroll = ft.ScrollMode.AUTO
    page.padding = 15
    page.add(
        ft.Text('Compose', size=22, weight=ft.FontWeight.BOLD),
        ft.Container(height=10),
        ft.Dropdown(
            ref=recipient_field,
            label='Recipient',
            options=[ft.dropdown.Option(r) for r in sorted(set(recipients))],
            width=page.width or 350,
        ),
        ft.Container(height=10),
        ft.TextField(ref=subject_field, label='Subject', hint_text='Optional', width=page.width or 350),
        ft.Container(height=10),
        ft.TextField(
            ref=message_field,
            label='Message',
            hint_text='Your plaintext message...',
            multiline=True,
            min_lines=5,
            max_lines=10,
            width=page.width or 350,
        ),
        ft.Container(height=15),
        ft.ElevatedButton(
            ref=send_btn,
            text='Encrypt & Send',
            icon=ft.icons.SEND,
            on_click=do_send,
            width=page.width or 350,
        ),
        ft.Container(height=10),
        ft.Text(ref=status_ref, size=13),
    )

# ─── Page: Inbox ───────────────────────────────────────────────────────────────

def inbox_page(page: Page):
    """Inbox — list and decrypt messages."""
    loading_ref = ft.Ref[ft.Text]()
    list_view = ft.Ref[ft.ListView]()
    refresh_btn = ft.Ref[ft.IconButton]()

    messages = []

    def load_messages():
        loading_ref.current.value = 'Loading...'
        page.update()
        list_view.current.controls.clear()
        try:
            client = get_client()
            messages.clear()
            messages.extend(client.list_messages(limit=100))
            client.close()

            if not messages:
                list_view.current.controls.append(
                    ft.Text('No messages', italic=True, color=ft.colors.GREY)
                )
            else:
                for m in messages:
                    ts = (m.get('timestamp') or '')[:16]
                    sender = m.get('sender', 'unknown')
                    subject = m.get('subject') or '(no subject)'
                    fid = m.get('id')
                    list_view.current.controls.append(
                        ft.ListTile(
                            leading=ft.Icon(ft.icons.MAIL_OUTLINE),
                            title=ft.Text(subject, weight=ft.FontWeight.W_600),
                            subtitle=ft.Text(f'From: {sender}  •  {ts}', size=11, color=ft.colors.GREY),
                            on_click=lambda e, mid=fid: decrypt_message(mid),
                        )
                    )
        except Exception as ex:
            list_view.current.controls.append(ft.Text(f'Error: {ex}', color=ft.colors.ERROR))
        finally:
            loading_ref.current.value = ''
            page.update()

    def decrypt_message(msg_id):
        dlg = ft.AlertDialog(title=ft.Text(f'Message #{msg_id}'), loading=True)
        page.dialog = dlg
        dlg.open = True
        page.update()

        try:
            client = get_client()
            m = client.get_message(msg_id)
            plaintext = m.get('plaintext', '(empty)')
            sender = m.get('sender', '')
            ts = m.get('timestamp', '')[:16]
            dlg.title = ft.Text(f'From: {sender}  •  {ts}')
            dlg.content = ft.Text(
                plaintext,
                white_space=ft.WhiteSpace.PRE_WRAP,
                selectable=True,
            )
            dlg.actions = [
                ft.TextButton('Close', on_click=lambda e: close_dlg()),
                ft.IconButton(ft.icons.DELETE, on_click=lambda e: delete_message(msg_id)),
            ]
        except Exception as ex:
            dlg.content = ft.Text(f'Error: {ex}', color=ft.colors.ERROR)
            dlg.actions = [ft.TextButton('Close', on_click=lambda e: close_dlg())]
        finally:
            page.update()

    def close_dlg():
        page.dialog.open = False
        page.update()

    def delete_message(msg_id):
        try:
            client = get_client()
            client.delete_message(msg_id)
            client.close()
            close_dlg()
            load_messages()
        except Exception as ex:
            close_dlg()
            status_ref.current.value = f'Delete failed: {ex}'
            page.update()

    page.title = 'Inbox'
    page.padding = 10
    page.appbar = ft.AppBar(
        title=ft.Text('Inbox'),
        actions=[
            ft.IconButton(ft.icons.REFRESH, ref=refresh_btn, on_click=lambda e: load_messages()),
        ],
    )
    status_ref = ft.Ref[ft.Text]()
    page.navigation_bar = _nav_bar(page)
    page.add(
        ft.Text(ref=loading_ref, size=13, color=ft.colors.GREY),
        ft.ListView(ref=list_view, expand=True, spacing=5),
        ft.Text(ref=status_ref, size=12, color=ft.colors.ERROR),
    )
    load_messages()

# ─── Page: Sent ───────────────────────────────────────────────────────────────

def sent_page(page: Page):
    """Sent log — messages sent via API."""
    loading_ref = ft.Ref[ft.Text]()
    list_view = ft.Ref[ft.ListView]()

    def load():
        loading_ref.current.value = 'Loading...'
        page.update()
        list_view.current.controls.clear()
        try:
            client = get_client()
            rows = client.list_messages(direction='sent', limit=100)
            client.close()
            if not rows:
                list_view.current.controls.append(ft.Text('No sent messages', italic=True, color=ft.colors.GREY))
            else:
                for m in rows:
                    ts = (m.get('timestamp') or '')[:16]
                    recipient = m.get('recipient', '')
                    subject = m.get('subject') or '(no subject)'
                    fid = m.get('id')
                    list_view.current.controls.append(
                        ft.ListTile(
                            leading=ft.Icon(ft.icons.SEND),
                            title=ft.Text(f'To: {recipient}', weight=ft.FontWeight.W_600),
                            subtitle=ft.Text(f'{subject}  •  {ts}', size=11, color=ft.colors.GREY),
                            on_click=lambda e, mid=fid: view_sent(mid),
                        )
                    )
        except Exception as ex:
            list_view.current.controls.append(ft.Text(f'Error: {ex}', color=ft.colors.ERROR))
        finally:
            loading_ref.current.value = ''
            page.update()

    def view_sent(msg_id):
        dlg = ft.AlertDialog(loading=True, title=ft.Text(f'Message #{msg_id}'))
        page.dialog = dlg
        dlg.open = True
        page.update()
        try:
            client = get_client()
            m = client.get_message(msg_id)
            recipient = m.get('recipient', '')
            subject = m.get('subject', '')
            plaintext = m.get('plaintext', '(empty)')
            ts = m.get('timestamp', '')[:16]
            dlg.title = ft.Text(f'To: {recipient}  •  {subject}  •  {ts}')
            dlg.content = ft.Text(plaintext, white_space=ft.WhiteSpace.PRE_WRAP, selectable=True)
            dlg.actions = [ft.TextButton('Close', on_click=lambda e: close_dlg())]
        except Exception as ex:
            dlg.content = ft.Text(f'Error: {ex}', color=ft.colors.ERROR)
            dlg.actions = [ft.TextButton('Close', on_click=lambda e: close_dlg())]
        finally:
            page.update()

    def close_dlg():
        page.dialog.open = False
        page.update()

    page.title = 'Sent'
    page.padding = 10
    page.navigation_bar = _nav_bar(page)
    page.add(
        ft.Text('Sent Messages', size=18, weight=ft.FontWeight.BOLD),
        ft.Container(height=10),
        ft.Text(ref=loading_ref, size=13, color=ft.colors.GREY),
        ft.ListView(ref=list_view, expand=True, spacing=5),
    )
    load()

# ─── Page: Keys ────────────────────────────────────────────────────────────────

def keys_page(page: Page):
    """Display public keys — read from server via HTML scrape (keys page)."""
    page.title = 'Keys'
    page.padding = 15
    page.navigation_bar = _nav_bar(page)
    page.add(
        ft.Text('Keys', size=22, weight=ft.FontWeight.BOLD),
        ft.Container(height=10),
        ft.Text(
            'Keys are managed on the desktop server.\n'
            'Open the web UI at /keys to import or delete keys.',
            size=13, color=ft.colors.GREY,
        ),
    )

# ─── Nav bar ─────────────────────────────────────────────────────────────────

def _nav_bar(page: Page):
    return ft.NavigationBar(
        selected_index=0,
        destinations=[
            ft.NavigationDestination(icon=ft.icons.COMPOSE, label='Compose'),
            ft.NavigationDestination(icon=ft.icons.INBOX, label='Inbox'),
            ft.NavigationDestination(icon=ft.icons.SEND, label='Sent'),
            ft.NavigationDestination(icon=ft.icons.KEY, label='Keys'),
        ],
        on_change=lambda e: _on_nav_change(e, page),
    )

def _on_nav_change(e, page: Page):
    idx = e.control.selected_index
    page.clean()
    if idx == 0:
        compose_page(page)
    elif idx == 1:
        inbox_page(page)
    elif idx == 2:
        sent_page(page)
    elif idx == 3:
        keys_page(page)

# ─── Main App ────────────────────────────────────────────────────────────────

def main_app(page: Page):
    page.clean()
    page.title = 'PGP Vault'
    page.padding = 0
    compose_page(page)

# ─── Entrypoint ──────────────────────────────────────────────────────────────

def main(page: Page):
    if not _server_url.current:
        connect_page(page)
    else:
        main_app(page)

ft.app(main)
