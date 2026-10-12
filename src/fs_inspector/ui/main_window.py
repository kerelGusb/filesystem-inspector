from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QFileDialog, QHeaderView, QMainWindow, QMessageBox, QSplitter, QTableWidget, QTableWidgetItem, QTreeWidget, QTreeWidgetItem

from fs_inspector.app.inspection import ImageOpenError, InspectionController
from fs_inspector.ui.hex_view import HexView


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
        self.table = QTableWidget(0, 3, self)
        self.table.setHorizontalHeaderLabels(("Field", "Value", "Bytes"))
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self.select_field)
        self.hex_view = HexView(self.controller.read_at, self.controller.size_of, self)
        self.hex_view.read_failed.connect(self.show_error)

        top = QSplitter(Qt.Orientation.Horizontal, self)
        top.addWidget(self.tree)
        top.addWidget(self.table)
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
            item = QTreeWidgetItem(self.tree, [node.title])
            item.setData(0, Qt.ItemDataRole.UserRole, node.ref)
        self.tree.setCurrentItem(self.tree.topLevelItem(0))
        return True

    def select_node(self, item, previous):
        if item is None:
            return
        try:
            node = self.controller.get_node(item.data(0, Qt.ItemDataRole.UserRole))
        except Exception as error:
            self.show_error(str(error))
            return
        self.fields = node.fields
        self.table.blockSignals(True)
        self.table.setRowCount(len(node.fields))
        for row, field in enumerate(node.fields):
            for column, value in enumerate((field.name, str(field.value), ", ".join(f"0x{span.offset:X}" for span in field.ranges))):
                self.table.setItem(row, column, QTableWidgetItem(value))
        self.table.clearSelection()
        self.table.blockSignals(False)
        self.hex_view.show_ranges(node.ranges, highlight=True)
        self.statusBar().showMessage(node.title)

    def select_field(self):
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            return
        field = self.fields[selected[0].row()]
        if field.ranges:
            self.hex_view.show_ranges(field.ranges, highlight=True)
        else:
            self.hex_view.clear_highlight()

    def show_error(self, message):
        self.statusBar().showMessage(message)
        QMessageBox.warning(self, "Cannot inspect image", message)

    def close_image(self):
        self.tree.blockSignals(True)
        self.tree.clear()
        self.tree.blockSignals(False)
        self.table.setRowCount(0)
        self.hex_view.clear()
        self.fields = ()
        self.source_id = None
        self.controller.close()
        self.setWindowTitle("Filesystem Inspector")

    def closeEvent(self, event):
        self.close_image()
        super().closeEvent(event)
