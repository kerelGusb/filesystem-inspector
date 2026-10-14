from concurrent.futures import ThreadPoolExecutor
from collections import namedtuple
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QFileDialog,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from fs_inspector.app.inspection import ImageOpenError, InspectionController, InspectionError
from fs_inspector.core.models import NodeRef, SourceRange
from fs_inspector.ui.hex_view import HexView


REF_ROLE = Qt.ItemDataRole.UserRole
CURSOR_ROLE = Qt.ItemDataRole.UserRole.value + 1
LOADED_ROLE = Qt.ItemDataRole.UserRole.value + 2
CYCLE_ROLE = Qt.ItemDataRole.UserRole.value + 3
LINK_PAGE_SIZE = 64


class _PendingOpen(namedtuple("_PendingOpen", "controller future")):
    __slots__ = ()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._controller = InspectionController()
        self._fields = ()
        self._source_id = None
        self._open_executor = None
        self._pending_open = None
        self._open_poll = QTimer(self)
        self._open_poll.setInterval(20)
        self._open_poll.timeout.connect(self._finish_pending_open)
        self.setWindowTitle("Filesystem Inspector")
        self.resize(1280, 720)

        self.open_action = QAction("Open image…", self)
        self.open_action.setShortcut("Ctrl+O")
        self.open_action.triggered.connect(self._choose_image)
        self.jump_action = QAction("Go to offset", self)
        self.jump_action.setShortcut("Ctrl+G")
        self.jump_action.setEnabled(False)
        self.jump_action.triggered.connect(self.jump_to_offset)
        file_menu = self.menuBar().addMenu("File")
        file_menu.addAction(self.open_action)
        toolbar = self.addToolBar("Image")
        toolbar.addAction(self.open_action)
        toolbar.addSeparator()
        self.offset_input = QLineEdit(self)
        self.offset_input.setPlaceholderText("Physical offset (0x… or decimal)")
        self.offset_input.setFixedWidth(230)
        self.offset_input.setEnabled(False)
        self.offset_input.returnPressed.connect(self.jump_to_offset)
        toolbar.addWidget(self.offset_input)
        toolbar.addAction(self.jump_action)

        self.navigation = QTreeWidget(self)
        self.navigation.setHeaderLabel("Structures")
        self.navigation.currentItemChanged.connect(self._navigation_changed)
        self.navigation.itemExpanded.connect(self._item_expanded)
        self.navigation.itemActivated.connect(self._item_activated)

        self.field_table = QTableWidget(0, 4, self)
        self.field_table.setHorizontalHeaderLabels(("Field", "Value", "Offset", "Bytes"))
        self.field_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.field_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.field_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.field_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.field_table.horizontalHeader().setStretchLastSection(True)
        self.field_table.itemSelectionChanged.connect(self._field_selected)
        self.diagnostic_label = QLabel(self)
        self.diagnostic_label.setWordWrap(True)
        self.diagnostic_label.setStyleSheet(
            "QLabel { background: #FFF0C2; color: #402C00; padding: 6px; }"
        )
        self.diagnostic_label.hide()
        details = QWidget(self)
        details_layout = QVBoxLayout(details)
        details_layout.setContentsMargins(0, 0, 0, 0)
        details_layout.addWidget(self.diagnostic_label)
        details_layout.addWidget(self.field_table, 1)

        self.hex_view = HexView(
            lambda source_id, offset, length: self._controller.read_at(source_id, offset, length),
            lambda source_id: self._controller.size_of(source_id),
            self,
        )
        self.hex_view.read_failed.connect(self._show_error)
        structure_panes = QSplitter(Qt.Orientation.Horizontal, self)
        structure_panes.addWidget(self.navigation)
        structure_panes.addWidget(details)
        structure_panes.setSizes((320, 960))
        panes = QSplitter(Qt.Orientation.Vertical, self)
        panes.addWidget(structure_panes)
        panes.addWidget(self.hex_view)
        panes.setSizes((400, 300))
        self.setCentralWidget(panes)
        self.statusBar().showMessage("Open an image to inspect it")

    def _choose_image(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open filesystem image")
        if path:
            self.open_image_async(path)

    def open_image_async(self, path):
        self.close_image()
        if self._open_executor is None:
            self._open_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="image-open")
        controller = InspectionController()
        future = self._open_executor.submit(controller.open_image, path)
        self._pending_open = _PendingOpen(controller, future)
        self.statusBar().showMessage(f"Opening image: {path}")
        self._open_poll.start()

    def _finish_pending_open(self):
        pending = self._pending_open
        if pending is None or not pending.future.done():
            return
        self._pending_open = None
        self._open_poll.stop()
        try:
            opened = pending.future.result()
        except Exception as exc:
            pending.controller.close()
            message = str(exc) if isinstance(exc, ImageOpenError) else f"Cannot open image: {exc}"
            self.statusBar().showMessage(message)
            QMessageBox.warning(self, "Cannot open image", message)
            return
        self._controller = pending.controller
        self._display_opened(opened)

    def _cancel_pending_open(self):
        pending = self._pending_open
        if pending is None:
            return
        self._pending_open = None
        self._open_poll.stop()
        pending.future.cancel()
        pending.future.add_done_callback(lambda _future: pending.controller.close())

    def open_image(self, path):
        self.close_image()
        try:
            opened = self._controller.open_image(path)
        except ImageOpenError as exc:
            self.setWindowTitle("Filesystem Inspector")
            self.statusBar().showMessage(str(exc))
            QMessageBox.warning(self, "Cannot open image", str(exc))
            return False

        self._display_opened(opened)
        return True

    def _display_opened(self, opened):
        self.jump_action.setEnabled(True)
        self.offset_input.setEnabled(True)
        self._source_id = opened.source_id
        self.setWindowTitle(f"Filesystem Inspector — {opened.path.name}")
        for node in opened.root_nodes:
            self._add_node_item(self.navigation.invisibleRootItem(), node.title, node.ref)
        self.statusBar().showMessage(f"{opened.plugin_name}: {opened.path}")
        self.navigation.setCurrentItem(self.navigation.topLevelItem(0))

    def close_image(self):
        self._cancel_pending_open()
        self._controller.close()
        self._clear_views()
        self.jump_action.setEnabled(False)
        self.offset_input.setEnabled(False)
        self.setWindowTitle("Filesystem Inspector")
        self.statusBar().showMessage("Open an image to inspect it")

    def _clear_views(self):
        self.jump_action.setEnabled(False)
        self.offset_input.setEnabled(False)
        self.offset_input.clear()
        self.navigation.blockSignals(True)
        self.navigation.clear()
        self.navigation.blockSignals(False)
        self._clear_details()
        self._source_id = None

    def _clear_details(self):
        self.field_table.blockSignals(True)
        self.field_table.setRowCount(0)
        self.field_table.blockSignals(False)
        self._fields = ()
        self.diagnostic_label.clear()
        self.diagnostic_label.hide()
        self.hex_view.clear()

    def _add_node_item(
        self, parent, label, ref,
        *, target_has_links = None,
    ):
        ancestor = parent
        repeats_ancestor = False
        while ancestor is not None:
            if ancestor.data(0, REF_ROLE) == ref:
                repeats_ancestor = True
                break
            ancestor = ancestor.parent()
        item = QTreeWidgetItem(parent, (f"{label} [already in path]" if repeats_ancestor else label,))
        item.setData(0, REF_ROLE, ref)
        if repeats_ancestor:
            item.setData(0, CYCLE_ROLE, True)
            item.setToolTip(
                0,
                "This link points to an ancestor already shown above. "
                "Select it to inspect the structure; expand the earlier item to see its links.",
            )
        elif target_has_links is False:
            item.setData(0, LOADED_ROLE, True)
        else:
            QTreeWidgetItem(item, ("Expand to load links",)).setDisabled(True)
        return item

    def _item_expanded(self, item):
        cursor = item.data(0, CURSOR_ROLE)
        if isinstance(cursor, str):
            parent = item.parent()
            if parent is not None:
                self._load_links(parent, cursor, marker=item)
        elif (
            isinstance(item.data(0, REF_ROLE), NodeRef)
            and not item.data(0, LOADED_ROLE)
            and not item.data(0, CYCLE_ROLE)
        ):
            self._load_links(item, None)

    def _item_activated(self, item):
        if isinstance(item.data(0, CURSOR_ROLE), str):
            self._item_expanded(item)

    def _load_links(
        self, parent, cursor, *, marker = None
    ):
        ref = parent.data(0, REF_ROLE)
        if not isinstance(ref, NodeRef):
            return
        try:
            page = self._controller.list_links(ref, cursor, LINK_PAGE_SIZE)
            if page.next_cursor is not None and (
                page.next_cursor == cursor or not page.links
            ):
                raise InspectionError("Plugin returned a non-advancing link page")
        except InspectionError as exc:
            self._show_error(str(exc))
            return
        if marker is None:
            parent.takeChildren()
            parent.setData(0, LOADED_ROLE, True)
        else:
            parent.removeChild(marker)
        for link in page.links:
            self._add_node_item(
                parent, link.label, link.target, target_has_links=link.target_has_links
            )
        if page.next_cursor is not None:
            more = QTreeWidgetItem(parent, ("Load more…",))
            more.setData(0, CURSOR_ROLE, page.next_cursor)
            QTreeWidgetItem(more, ("Next page",)).setDisabled(True)

    def jump_to_offset(self):
        if self._source_id is None:
            return
        value = self.offset_input.text().strip()
        try:
            if value.lower().startswith("0x"):
                digits = value[2:]
                if not digits or not digits.isascii():
                    raise ValueError("invalid hexadecimal offset")
                offset = int(digits, 16)
            elif value.isascii() and value.isdecimal():
                offset = int(value, 10)
            else:
                raise ValueError("enter a decimal offset or one prefixed with 0x")
            size = self._controller.size_of(self._source_id)
            if not 0 <= offset < size:
                raise ValueError(f"physical offset must be within [0, {size})")
        except ValueError as exc:
            self._show_error(f"Cannot jump to physical offset: {exc}")
            return
        self.field_table.clearSelection()
        if self.hex_view.show_ranges((SourceRange(self._source_id, offset, 1),), highlight=True):
            self.statusBar().showMessage(f"Physical offset {self._source_id}: 0x{offset:X}")

    def _navigation_changed(self, current):
        if current is None:
            return
        ref = current.data(0, Qt.ItemDataRole.UserRole)
        if not isinstance(ref, NodeRef):
            self._clear_details()
            if isinstance(current.data(0, CURSOR_ROLE), str):
                self.statusBar().showMessage("Expand or activate Load more to fetch the next page")
            return
        try:
            node = self._controller.get_node(ref)
        except InspectionError as exc:
            self._clear_details()
            self._show_error(str(exc))
            return
        self._show_node(node)

    def _show_node(self, node):
        self._fields = node.fields
        self.field_table.blockSignals(True)
        self.field_table.setRowCount(len(node.fields))
        for row, field in enumerate(node.fields):
            cells = (
                field.name,
                repr(field.value) if isinstance(field.value, bytes) else str(field.value),
                self._range_offsets(field.ranges),
                self._range_lengths(field.ranges),
            )
            for column, value in enumerate(cells):
                item = QTableWidgetItem(value)
                if field.description:
                    item.setToolTip(field.description)
                self.field_table.setItem(row, column, item)
        self.field_table.clearSelection()
        self.field_table.blockSignals(False)
        self.diagnostic_label.setText("; ".join(node.diagnostics))
        self.diagnostic_label.setVisible(bool(node.diagnostics))
        self.statusBar().showMessage("; ".join(node.diagnostics) if node.diagnostics else node.title)
        self.hex_view.show_ranges(node.ranges, highlight=True)

    def _show_error(self, message):
        self.statusBar().showMessage(message)
        QMessageBox.warning(self, "Cannot inspect image", message)

    def _field_selected(self):
        selected = self.field_table.selectionModel().selectedRows()
        if not selected:
            return
        field = self._fields[selected[0].row()]
        if field.ranges:
            if self.hex_view.show_ranges(field.ranges, highlight=True):
                self.statusBar().showMessage(
                    f"{field.name}: exact source bytes at {self._range_offsets(field.ranges)}"
                )
        else:
            self.hex_view.clear_highlight()
            self.statusBar().showMessage(f"{field.name}: no exact source byte range")

    def _range_offsets(self, ranges):
        return ", ".join(f"{span.source_id}: 0x{span.offset:X}" for span in ranges)

    def _range_lengths(self, ranges):
        return ", ".join(str(span.length) for span in ranges)

    def closeEvent(self, event):
        self.close_image()
        if self._open_executor is not None:
            self._open_executor.shutdown(wait=False, cancel_futures=True)
        super().closeEvent(event)
