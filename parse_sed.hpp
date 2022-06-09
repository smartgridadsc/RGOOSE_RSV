// For parsing XML data
#include "rapidxml-1.13/rapidxml.hpp"
#include "rapidxml-1.13/rapidxml_print.hpp"
#include "rapidxml-1.13/rapidxml_utils.hpp"

/* An aggregate of variables representing
 * information parsed from SED file
 */
struct ControlBlock
{
    std::string              hostIED{};
    std::string              cbType{};
    std::string              multicastIP{};
    std::string              appID{};
    std::string              vlanID{};
    std::string              cbName{};
    std::string              datSetName{};
    std::vector<std::string> datSetVector{};
    std::vector<std::string> subscribingIEDs{};
};

/* Function to parse SED file and get Control Blocks' information */
std::vector<ControlBlock> parse_sed(const char *filename)
{
    std::vector<ControlBlock> vector_of_ctrl_blks{};

    rapidxml::file<> xmlFile(filename);
    rapidxml::xml_document<> doc;
    doc.parse<0>(xmlFile.data());

    // Find out the root node: prints "Root Node's name: SCL" for a SED file
    rapidxml::xml_node<> *root_node = doc.first_node();
    if (static_cast<std::string>(root_node->name()) == "SCL")
    {
        std::cout << "[*] Successfully parsed XML data in " << filename << '\n'
                  << "Name of Root Node in SED file = " << root_node->name() << "\n\n";
    }
    else
    {
        std::cout << "Name of Root Node is not \"SCL\"! Please check format of SED file: " << filename << '\n';
        exit (EXIT_FAILURE);
    }

    // Create a map with key = IED Name & value = vector of LD(s) that contain Control Block(s)
    std::map<std::string, std::vector<std::string>> map_of_ld_with_cb;

    for (rapidxml::xml_node<> *lvl_1_node = root_node->first_node("Communication"); lvl_1_node; lvl_1_node = lvl_1_node->next_sibling("Communication"))
    {
        std::cout << "[*] Searching for Control Block(s) in <" << lvl_1_node->name() << "> element...\n";

        for (rapidxml::xml_node<> *lvl_2_node = lvl_1_node->first_node("SubNetwork"); lvl_2_node; lvl_2_node = lvl_2_node->next_sibling("SubNetwork"))
        {
            for (rapidxml::xml_node<> *lvl_3_node = lvl_2_node->first_node("ConnectedAP"); lvl_3_node; lvl_3_node = lvl_3_node->next_sibling("ConnectedAP"))
            {
                std::vector<std::string> vector_of_LDs_with_CBs{};

                for (rapidxml::xml_node<> *lvl_4_node = lvl_3_node->first_node(); lvl_4_node; lvl_4_node = lvl_4_node->next_sibling())
                {
                    rapidxml::xml_attribute<>* attr_tmp = nullptr;
                    ControlBlock CB_tmp{};

                    if (   (static_cast<std::string>(lvl_4_node->name()) == "GSE")
                        || (static_cast<std::string>(lvl_4_node->name()) == "SMV")   )
                    {
                        std::cout << "    "        << lvl_4_node->name() << " Control Block found in:\n"
                                  << "    -> "     << lvl_2_node->name() << ": " << lvl_2_node->first_attribute("name")->value() << '\n'
                                  << "        -> " << lvl_3_node->name() << ": " << lvl_3_node->first_attribute("iedName")->value() << '\n';

                        attr_tmp = lvl_4_node->first_attribute("ldInst");
                        if (attr_tmp)
                        {
                            vector_of_LDs_with_CBs.push_back(static_cast<std::string>(lvl_4_node->first_attribute("ldInst")->value()));
                        }
                        else
                        {
                            std::cout << "    [!] But 'ldInst' is not found in Control Block's node\n";
                            exit (EXIT_FAILURE);
                        }

                        /* Prepare Control Block information (partial) */
                        CB_tmp.hostIED = static_cast<std::string>(lvl_3_node->first_attribute("iedName")->value());
                        CB_tmp.cbType = static_cast<std::string>(lvl_4_node->name());

                        for (rapidxml::xml_node<> *nodeP = lvl_4_node->first_node("Address")->first_node("P");
                                nodeP;
                                    nodeP = nodeP->next_sibling())
                        {
                            std::string p_type = static_cast<std::string>(nodeP->first_attribute("type")->value());

                            if (p_type == "IP")
                            {
                                CB_tmp.multicastIP = nodeP->value();
                            }
                            else if (p_type == "APPID")
                            {
                                CB_tmp.appID = nodeP->value();
                            }
                            else if (p_type == "VLAN-ID")
                            {
                                CB_tmp.vlanID = nodeP->value();
                            }
                        }

                        // Not-yet-fully-qualified cbName
                        CB_tmp.cbName = static_cast<std::string>(lvl_4_node->first_attribute("cbName")->value());

                        vector_of_ctrl_blks.push_back(CB_tmp);
                    }

                }

                if (!vector_of_LDs_with_CBs.empty())
                {
                    map_of_ld_with_cb[static_cast<std::string>(lvl_3_node->first_attribute("iedName")->value())] = vector_of_LDs_with_CBs;
                    std::cout << "    Saved " << vector_of_LDs_with_CBs.size() << " LD(s) with CB(s) for IED " << lvl_3_node->first_attribute("iedName")->value() << " - to be checked later...\n\n";
                }

            }
        }
    }

    std::cout << "[*] Found a total of " << vector_of_ctrl_blks.size() << " Control Block(s).\n\n";

    // Look for prefix <LDName>/<LNName> for each cbName
    for (auto item : map_of_ld_with_cb)
    {
        for (rapidxml::xml_node<> *lvl_1_node = root_node->first_node("IED");
                lvl_1_node;
                    lvl_1_node = lvl_1_node->next_sibling("IED"))
        {
            if (static_cast<std::string>(lvl_1_node->first_attribute("name")->value()) == item.first)
            {
                std::cout << "[*] Checking Control Block(s) in IED name = " << lvl_1_node->first_attribute("name")->value() << "...\n";

                // Each IED has only one AccessPoint (no need to iterate with for-loop)
                rapidxml::xml_node<> *nodeAP = lvl_1_node->first_node("AccessPoint");

                for (rapidxml::xml_node<> *nodeLDev = nodeAP->first_node("LDevice");
                        nodeLDev;
                            nodeLDev = nodeLDev->next_sibling("LDevice"))
                {
                    // Check for match with ldInst from Control Block information under Communication node
                    if (   (!item.second.empty())
                        && (static_cast<std::string>(nodeLDev->first_attribute("inst")->value()) == item.second[item.second.size() - 1])   )
                    {
                        std::string cbName{};
                        std::string datSetName{};
                        std::vector<std::string> datSetVector{};

                        // Assume only 1x LN0 node per LDevice node
                        rapidxml::xml_node<> *nodeLN = nodeLDev->first_node("LN0");

                        for (rapidxml::xml_node<> *nodeCB = nodeLN->first_node();
                                nodeCB;
                                    nodeCB = nodeCB->next_sibling())
                        {
                            // Check for presence of a Control Block
                            if (   (static_cast<std::string>(nodeCB->name()) == "GSEControl")
                                || (static_cast<std::string>(nodeCB->name()) == "SampledValueControl")   )
                            {
                                cbName = static_cast<std::string>(nodeCB->first_attribute("Name")->value());
                                datSetName = static_cast<std::string>(nodeCB->first_attribute("datSet")->value());

                                for (rapidxml::xml_node<> *nodeDataSet = nodeLN->first_node("DataSet");
                                        nodeDataSet;
                                            nodeDataSet = nodeDataSet->next_sibling("DataSet"))
                                {
                                    /*
                                     * Check that the parsed DataSet has the same datSetName (not yet fully qualified)
                                     * as the Control Block, then compile the Cyber component for the CPMapping.
                                     */
                                    if (static_cast<std::string>(nodeDataSet->first_attribute("name")->value()) == datSetName)
                                    {
                                        for (rapidxml::xml_node<> *nodeFCDA = nodeDataSet->first_node("FCDA");
                                                nodeFCDA;
                                                    nodeFCDA = nodeFCDA->next_sibling())
                                        {
                                            std::string currentCyber{};

                                            // Assume required attribute names are present and correctly formed (no error-checking implemented)
                                            currentCyber = static_cast<std::string>(lvl_1_node->first_attribute("name")->value())
                                                            + '.'
                                                            + static_cast<std::string>(nodeFCDA->first_attribute("lnClass")->value())
                                                            + '.'
                                                            + static_cast<std::string>(nodeFCDA->first_attribute("doName")->value())
                                                            + '.'
                                                            + static_cast<std::string>(nodeFCDA->first_attribute("daName")->value());

                                            datSetVector.push_back(currentCyber);
                                        }
                                    }
                                    if (datSetVector.empty())
                                    {
                                        std::cout << "\t[!] Couldn't find a matching datSet Name in LN Node as the Control Block's.\n";
                                        exit (EXIT_FAILURE);
                                    }
                                }

                                for (size_t i = 0; i < vector_of_ctrl_blks.size() ; i++)
                                {
                                    /* Check if Control Block in vector matches
                                     * the current Control Block parsed from the IED section of SED file
                                     */
                                    if (   (vector_of_ctrl_blks[i].hostIED == item.first)
                                        && (vector_of_ctrl_blks[i].cbName == cbName)   )
                                    {
                                        std::string prefix = static_cast<std::string>(nodeLDev->first_attribute("inst")->value())
                                                            + '/'
                                                            + static_cast<std::string>(nodeLN->first_attribute("lnClass")->value())
                                                            + '.';
                                        cbName = prefix + cbName;
                                        datSetName = prefix + datSetName;

                                        /* Prepare Control Block information (full) */
                                        vector_of_ctrl_blks[i].cbName = cbName;
                                        vector_of_ctrl_blks[i].datSetName = datSetName;
                                        vector_of_ctrl_blks[i].datSetVector = datSetVector;

                                        for (rapidxml::xml_node<> *nodeIEDName = nodeCB->first_node("IEDName");
                                                nodeIEDName;
                                                    nodeIEDName = nodeIEDName->next_sibling("IEDName"))
                                        {
                                            vector_of_ctrl_blks[i].subscribingIEDs.push_back(static_cast<std::string>(nodeIEDName->value()));
                                        }

                                        /*
                                         * Since we found the current matching Control Block already,
                                         * skip checking the rest of the saved Control Blocks in:
                                         *  // for (size_t i = 0; i < vector_of_ctrl_blks.size() ; i++)
                                         */
                                        break;
                                    }
                                }
                            }
                        }
                        item.second.pop_back();
                        if (item.second.empty())
                        {
                            // Skip checking other LDevices if there're no more Control Blocks to find
                            break;
                        }
                    }
                }
            }
        }
    }

    std::cout << "\n[*] Finished parsing SED file for Control Blocks.\n\n\n";
    return vector_of_ctrl_blks;
}
