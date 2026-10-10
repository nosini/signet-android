// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet.vault

import app.keemobile.kotpass.models.*
import app.keemobile.kotpass.xml.*
import java.io.InputStream
import javax.xml.parsers.DocumentBuilderFactory

/** Reject unmodeled XML before editing, so a codec upgrade cannot silently discard extensions. */
object SafeXml : XmlContentParser {
    private fun names(value: String) = value.split(' ').toSet()

    private val children =
        mapOf(
            "KeePassFile" to names("Meta Root"),
            "Root" to names("Group DeletedObjects"),
            "Meta" to
                names(
                    "Generator HeaderHash SettingsChanged DatabaseName DatabaseNameChanged DatabaseDescription DatabaseDescriptionChanged DefaultUserName DefaultUserNameChanged MaintenanceHistoryDays Color MasterKeyChanged MasterKeyChangeRec MasterKeyChangeForce MemoryProtection CustomIcons RecycleBinEnabled RecycleBinUUID RecycleBinChanged EntryTemplatesGroup EntryTemplatesGroupChanged HistoryMaxItems HistoryMaxSize LastSelectedGroup LastTopVisibleGroup Binaries CustomData"
                ),
            "Group" to
                names(
                    "UUID Name Notes IconID CustomIconUUID Times IsExpanded DefaultAutoTypeSequence EnableAutoType EnableSearching LastTopVisibleEntry PreviousParentGroup Tags CustomData Group Entry"
                ),
            "Entry" to
                names(
                    "UUID IconID CustomIconUUID ForegroundColor BackgroundColor OverrideURL Times AutoType String Tags Binary History CustomData PreviousParentGroup QualityCheck"
                ),
            "Times" to
                names(
                    "CreationTime LastAccessTime LastModificationTime LocationChanged ExpiryTime Expires UsageCount"
                ),
            "MemoryProtection" to
                names("ProtectTitle ProtectUserName ProtectPassword ProtectURL ProtectNotes"),
            "CustomIcons" to names("Icon"),
            "Icon" to names("UUID Data Name LastModificationTime"),
            "CustomData" to names("Item"),
            "Item" to names("Key Value LastModificationTime"),
            "String" to names("Key Value"),
            "Binary" to names("Key Value"),
            "Binaries" to names("Binary"),
            "AutoType" to names("Enabled DataTransferObfuscation DefaultSequence Association"),
            "Association" to names("Window KeystrokeSequence"),
            "History" to names("Entry"),
            "DeletedObjects" to names("DeletedObject"),
            "DeletedObject" to names("UUID DeletionTime"),
        )

    override fun unmarshalContent(
        xmlData: ByteArray,
        contextBlock: (Meta) -> XmlContext.Decode,
    ): DatabaseContent {
        val text =
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(xmlData))
                .toString()
        require(!text.contains('\u0000')) { "KeePass XML must use UTF-8" }
        require(!Regex("<!\\s*(DOCTYPE|ENTITY)", RegexOption.IGNORE_CASE).containsMatchIn(text)) {
            "External XML declarations are not supported"
        }
        val factory =
            DocumentBuilderFactory.newInstance().apply {
                isExpandEntityReferences = false
                isNamespaceAware = true
            }
        val document = factory.newDocumentBuilder().parse(xmlData.inputStream())
        val identities = mutableSetOf<String>()
        fun direct(node: org.w3c.dom.Node, name: String): org.w3c.dom.Node? =
            (0 until node.childNodes.length)
                .asSequence()
                .map { node.childNodes.item(it) }
                .firstOrNull { it.nodeName == name }
        fun validate(node: org.w3c.dom.Node, depth: Int = 0) {
            require(depth <= 128) { "KeePass XML is nested too deeply" }
            if (node.nodeType == org.w3c.dom.Node.ELEMENT_NODE) {
                val parent = node.parentNode
                if (node.nodeName == "Group" || node.nodeName == "Entry") {
                    val id =
                        direct(node, "UUID")?.textContent?.trim() ?: error("Missing KeePass UUID")
                    require(java.util.Base64.getDecoder().decode(id).size == 16) {
                        "Invalid KeePass UUID"
                    }
                    if (parent.nodeName == "History")
                        require(id == direct(parent.parentNode, "UUID")?.textContent?.trim()) {
                            "History UUID differs from entry UUID"
                        }
                    else require(identities.add(id)) { "Duplicate KeePass UUID" }
                }

                val expected =
                    if (parent.nodeType == org.w3c.dom.Node.DOCUMENT_NODE) setOf("KeePassFile")
                    else if (
                        parent.nodeName == "Binary" && parent.parentNode.nodeName == "Binaries"
                    )
                        emptySet()
                    else children[parent.nodeName].orEmpty()
                require(node.nodeName in expected) {
                    "Unmodeled KeePass XML element: ${node.nodeName}. The vault was not changed."
                }
                for (i in 0 until node.attributes.length) require(
                    node.attributes.item(i).nodeName in
                        setOf("ID", "Ref", "Protected", "ProtectInMemory", "Compressed")
                ) {
                    "Unmodeled KeePass XML attribute. The vault was not changed."
                }
            }
            for (i in 0 until node.childNodes.length) validate(node.childNodes.item(i), depth + 1)
        }
        validate(document.documentElement)
        return DefaultXmlContentParser.unmarshalContent(xmlData, contextBlock)
    }

    override fun unmarshalContent(
        source: InputStream,
        contextBlock: (Meta) -> XmlContext.Decode,
    ): DatabaseContent = unmarshalContent(source.readBytes(), contextBlock)

    override fun marshalContent(
        context: XmlContext.Encode,
        content: DatabaseContent,
        pretty: Boolean,
    ): String = DefaultXmlContentParser.marshalContent(context, content, pretty)
}
