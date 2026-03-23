/**
 * Sidebar table rendering — shared module.
 *
 * This file is the single source of truth for the sidebar table columns.
 * It is bundled by esbuild into out/webview/sidebar-table.js and loaded by
 * BeadsSidebarProvider in extension.ts.
 *
 * IMPORTANT: Keep the visible column list in sync with the `tableColumns`
 * array in board.js.  When you add/remove/rename a column in the main board
 * table view you should update this file too (and vice-versa) — having both
 * in the same repository makes that easy to catch in code review.
 */

// Simple HTML-escape helper (no external deps needed here)
function escHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

/**
 * Columns rendered in the sidebar, mirroring the main board table view.
 * Each entry has an `id`, `label`, and `render(card)` method.
 *
 * Columns kept in sync with tableColumns in board.js:
 *   type | id | title | status | priority | assignee | labels | updated_at
 */
const SIDEBAR_COLUMNS = [
    {
        id: 'type',
        label: 'Type',
        render: (c) => {
            const type = c.issue_type || 'task';
            return `<span class="badge badge-type-${escHtml(type)}">${escHtml(type)}</span>`;
        }
    },
    {
        id: 'id',
        label: 'ID',
        render: (c) => `<span class="table-id" title="${escHtml(c.id)}">${escHtml(c.id.slice(-8))}</span>`
    },
    {
        id: 'title',
        label: 'Title',
        render: (c) => `<span class="table-title">${escHtml(c.title)}</span>`
    },
    {
        id: 'status',
        label: 'Status',
        render: (c) => `<span class="badge">${escHtml(c.status || 'open')}</span>`
    },
    {
        id: 'priority',
        label: 'P',
        render: (c) => `<span class="badge badge-priority-${c.priority != null ? c.priority : 2}">P${c.priority != null ? c.priority : 2}</span>`
    },
    {
        id: 'assignee',
        label: 'Assignee',
        render: (c) => {
            if (c.assignee) {
                return `<span class="badge badge-assignee">${escHtml(c.assignee)}</span>`;
            }
            return `<span class="badge badge-assignee badge-unassigned">Unassigned</span>`;
        }
    },
    {
        id: 'labels',
        label: 'Labels',
        render: (c) => {
            if (!c.labels || c.labels.length === 0) return '';
            const badges = c.labels.slice(0, 3).map(l => `<span class="badge">#${escHtml(l)}</span>`).join(' ');
            const more = c.labels.length > 3 ? ` <span class="badge">+${c.labels.length - 3}</span>` : '';
            return badges + more;
        }
    },
    {
        id: 'updated_at',
        label: 'Updated',
        render: (c) => {
            if (!c.updated_at) return '';
            const date = new Date(c.updated_at);
            return `<span class="table-date">${date.toLocaleDateString()}</span>`;
        }
    }
];

/**
 * Render an array of issue cards into the given container element as a table.
 * Uses the same `.issues-table` CSS classes as the main Kanban board table view.
 *
 * @param {HTMLElement} container - Element to write HTML into.
 * @param {Array}       cards     - Array of EnrichedCard objects.
 */
function renderSidebarTable(container, cards) {
    if (!container) return;

    if (!cards || cards.length === 0) {
        container.innerHTML = '<div class="empty-msg">No issues found</div>';
        return;
    }

    const headerCells = SIDEBAR_COLUMNS
        .map(col => `<th>${escHtml(col.label)}</th>`)
        .join('');

    const rows = cards.map(c => {
        const cells = SIDEBAR_COLUMNS
            .map(col => `<td>${col.render(c)}</td>`)
            .join('');
        return `<tr>${cells}</tr>`;
    }).join('');

    container.innerHTML =
        '<table class="issues-table">' +
        `<thead><tr>${headerCells}</tr></thead>` +
        `<tbody>${rows}</tbody>` +
        '</table>';
}

// Expose on window so the sidebar webview HTML can call it directly.
window.renderSidebarTable = renderSidebarTable;
