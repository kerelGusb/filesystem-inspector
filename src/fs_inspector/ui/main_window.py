from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QFileDialog, QHeaderView, QLabel, QMainWindow, QMessageBox, QSplitter, QTableWidget, QTableWidgetItem, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

from fs_inspector.app.inspection import ImageOpenError, InspectionController
from fs_inspector.ui.hex_view import HexView


CURSOR_ROLE = Qt.ItemDataRole.UserRole.value + 1
LOADED_ROLE = Qt.ItemDataRole.UserRole.value + 2


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.controller = InspectionController()
        self.fields = ()
        self.source_id = None
        self.setWindowTitle("Filesystem Inspector")
        self.resize(1100, 700)

        menu = self.menuBar().addMenu("File")
        open_action = QAction("Open image...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.choose_image)
        menu.addAction(open_action)

        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabel("Structures")
        self.tree.currentItemChanged.connect(self.select_node)
        self.tree.itemExpanded.connect(self.expand_item)
        self.tree.itemActivated.connect(self.activate_item)
        self.table = QTableWidget(0, 4, self)
        self.table.setHorizontalHeaderLabels(("Field", "Value", "Offset", "Bytes"))
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self.select_field)
        self.diagnostic_label = QLabel(self)
        self.diagnostic_label.setWordWrap(True)
        self.diagnostic_label.setStyleSheet("QLabel { background: #FFF0C2; color: #402C00; padding: 6px; }")
        self.diagnostic_label.hide()
        details = QWidget(self)
        details_layout = QVBoxLayout(details)
        details_layout.setContentsMargins(0, 0, 0, 0)
        details_layout.addWidget(self.diagnostic_label)
        details_layout.addWidget(self.table)
        self.hex_view = HexView(self.controller.read_at, self.controller.size_of, self)
        self.hex_view.read_failed.connect(self.show_error)

        top = QSplitter(Qt.Orientation.Horizontal, self)
        top.addWidget(self.tree)
        top.addWidget(details)
        whole = QSplitter(Qt.Orientation.Vertical, self)
        whole.addWidget(top)
        whole.addWidget(self.hex_view)
        self.setCentralWidget(whole)
        self.statusBar().showMessage("Open an image")

    def choose_image(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open filesystem image")
        if path:
            self.open_image(path)

    def open_image(self, path):
        self.close_image()
        try:
            opened = self.controller.open_image(path)
        except ImageOpenError as error:
            self.show_error(str(error))
            return False
        self.source_id = opened.source_id
        self.setWindowTitle(f"Filesystem Inspector — {Path(path).name}")
        for node in opened.root_nodes:
            self.add_node(self.tree.invisibleRootItem(), node.title, node.ref)
        self.tree.setCurrentItem(self.tree.topLevelItem(0))
        return True

    def add_node(self, parent, label, ref, expandable=True):
        ancestor = parent
        while ancestor is not None:
            if ancestor.data(0, Qt.ItemDataRole.UserRole) == ref:
                label += " [already in path]"
                expandable = False
                break
            ancestor = ancestor.parent()
        item = QTreeWidgetItem(parent, [label])
        item.setData(0, Qt.ItemDataRole.UserRole, ref)
        if expandable:
            QTreeWidgetItem(item, ["Expand to load links"]).setDisabled(True)
        return item

    def expand_item(self, item):
        cursor = item.data(0, CURSOR_ROLE)
        if isinstance(cursor, str):
            parent = item.parent()
            if parent is not None:
                parent.removeChild(item)
                self.load_links(parent, cursor)
        elif item.data(0, Qt.ItemDataRole.UserRole) is not None and not item.data(0, LOADED_ROLE):
            item.takeChildren()
            item.setData(0, LOADED_ROLE, True)
            self.load_links(item, None)

    def activate_item(self, item):
        if isinstance(item.data(0, CURSOR_ROLE), str):
            self.expand_item(item)

    def load_links(self, parent, cursor):
        ref = parent.data(0, Qt.ItemDataRole.UserRole)
        try:
            page = self.controller.list_links(ref, cursor, 64)
        except Exception as error:
            self.show_error(str(error))
            return
        for link in page.links:
            self.add_node(parent, link.label, link.target, link.target_has_links is not False)
        if page.next_cursor is not None:
            more = QTreeWidgetItem(parent, ["Load more..."])
            more.setData(0, CURSOR_ROLE, page.next_cursor)
            QTreeWidgetItem(more, ["Next page"]).setDisabled(True)

    def select_node(self, item, previous):
        if item is None:
            return
        ref = item.data(0, Qt.ItemDataRole.UserRole)
        if ref is None:
            return
        try:
            node = self.controller.get_node(ref)
        except Exception as error:
            self.table.setRowCount(0)
            self.hex_view.clear()
            self.show_error(str(error))
            return
        self.fields = node.fields
        self.table.blockSignals(True)
        self.table.setRowCount(len(node.fields))
        for row, field in enumerate(node.fields):
            values = (field.name,
                      repr(field.value) if isinstance(field.value, bytes) else str(field.value),
                      ", ".join(f"{span.source_id}: 0x{span.offset:X}" for span in field.ranges),
                      ", ".join(str(span.length) for span in field.ranges))
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                if field.description:
                    cell.setToolTip(field.description)
                self.table.setItem(row, column, cell)
        self.table.clearSelection()
        self.table.blockSignals(False)
        self.diagnostic_label.setText("; ".join(node.diagnostics))
        self.diagnostic_label.setVisible(bool(node.diagnostics))
        self.hex_view.show_ranges(node.ranges, highlight=True)
        self.statusBar().showMessage("; ".join(node.diagnostics) if node.diagnostics else node.title)

    def select_field(self):
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            return
        field = self.fields[selected[0].row()]
        if field.ranges:
            self.hex_view.show_ranges(field.ranges, highlight=True)
            self.statusBar().showMessage(f"{field.name}: source bytes highlighted")
        else:
            self.hex_view.clear_highlight()
            self.statusBar().showMessage(f"{field.name}: no exact source byte range")

    def show_error(self, message):
        self.statusBar().showMessage(message)
        QMessageBox.warning(self, "Cannot inspect image", message)

    def close_image(self):
        self.tree.blockSignals(True)
        self.tree.clear()
        self.tree.blockSignals(False)
        self.table.setRowCount(0)
        self.diagnostic_label.clear()
        self.diagnostic_label.hide()
        self.hex_view.clear()
        self.fields = ()
        self.source_id = None
        self.controller.close()
        self.setWindowTitle("Filesystem Inspector")

    def closeEvent(self, event):
        self.close_image()
        super().closeEvent(event)
