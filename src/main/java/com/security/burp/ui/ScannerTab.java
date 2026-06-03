package com.security.burp.ui;

import burp.api.montoya.ui.swing.SwingUtils;
import com.security.burp.scanner.EndpointRegistry;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * UI tab listing API endpoints discovered by the passive checks.
 *
 * <p>The table is backed by {@link EndpointRegistry} and refreshed by a
 * Swing timer. The timer is stopped via {@link #dispose()} when the
 * extension unloads, so this class leaks no resources.
 *
 * <p>Future popup dialogs from this tab should use
 * {@link SwingUtils#suiteFrame()} as their parent to ensure they appear on
 * the correct monitor in multi-display setups (BApp criterion #10).
 */
public final class ScannerTab {

    private static final int REFRESH_INTERVAL_MS = 5_000;

    private final EndpointRegistry registry;
    @SuppressWarnings("unused") // retained for future popups; see class javadoc.
    private final SwingUtils swingUtils;
    private final JPanel panel;
    private final EndpointTableModel model;
    private final JLabel statusLabel;
    private final Timer refreshTimer;

    public ScannerTab(EndpointRegistry registry, SwingUtils swingUtils) {
        this.registry = registry;
        this.swingUtils = swingUtils;
        this.model = new EndpointTableModel();
        this.statusLabel = new JLabel("0 endpoints discovered");
        this.panel = buildPanel();
        this.refreshTimer = new Timer(REFRESH_INTERVAL_MS, e -> refresh());
        refreshTimer.start();
    }

    public java.awt.Component component() {
        return panel;
    }

    /** Stops the refresh timer. Called from the unloading handler. */
    public void dispose() {
        refreshTimer.stop();
    }

    private JPanel buildPanel() {
        JPanel root = new JPanel(new BorderLayout());
        root.add(new JLabel("API endpoints discovered during scanning:"), BorderLayout.NORTH);
        root.add(new JScrollPane(new JTable(model)), BorderLayout.CENTER);
        root.add(statusLabel, BorderLayout.SOUTH);
        return root;
    }

    /**
     * Snapshot + sort runs on a SwingWorker background thread (the registry
     * can hold up to 10,000 entries). Only the lightweight model swap and
     * the status-label update touch the EDT. Avoids the multi-millisecond
     * EDT freeze the automated review flagged.
     */
    private void refresh() {
        new SwingWorker<List<EndpointRegistry.ApiEndpoint>, Void>() {
            @Override
            protected List<EndpointRegistry.ApiEndpoint> doInBackground() {
                List<EndpointRegistry.ApiEndpoint> sorted = new ArrayList<>(registry.snapshot());
                sorted.sort(Comparator.comparing(EndpointRegistry.ApiEndpoint::host)
                        .thenComparing(EndpointRegistry.ApiEndpoint::path));
                return sorted;
            }

            @Override
            protected void done() {
                try {
                    model.setRows(get());
                    statusLabel.setText(model.getRowCount() + " endpoints discovered");
                } catch (Exception ignored) {
                    // SwingWorker.get throws if doInBackground threw; we don't
                    // want a refresh failure to propagate to the EDT.
                }
            }
        }.execute();
    }

    /** Read-only view of {@link EndpointRegistry} sorted by host then path. */
    private static final class EndpointTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"Host", "Path", "Methods"};
        private List<EndpointRegistry.ApiEndpoint> rows = List.of();

        /** Called on the EDT with an already-sorted list. */
        void setRows(List<EndpointRegistry.ApiEndpoint> sorted) {
            this.rows = sorted;
            fireTableDataChanged();
        }

        @Override public int getRowCount()                  { return rows.size(); }
        @Override public int getColumnCount()               { return COLUMNS.length; }
        @Override public String getColumnName(int column)   { return COLUMNS[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            EndpointRegistry.ApiEndpoint endpoint = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> endpoint.host();
                case 1 -> endpoint.path();
                case 2 -> String.join(", ", endpoint.methods());
                default -> "";
            };
        }
    }
}
